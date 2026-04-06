from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from src.contracts import Entity
from src.pipeline import _enrich_iocs, _extract_entities, run


class _FakeProbabilities(list[float]):
    def argmax(self) -> int:
        return int(max(range(len(self)), key=lambda idx: self[idx]))


class _FakeModel:
    def __init__(self, label: str, probabilities: list[float]) -> None:
        self._label = label
        self._probabilities = probabilities
        self.predict_calls = 0
        self.predict_proba_calls = 0

    def predict(self, inputs: list[str]) -> list[str]:
        self.predict_calls += 1
        return [self._label for _ in inputs]

    def predict_proba(self, inputs: list[str]) -> list[_FakeProbabilities]:
        self.predict_proba_calls += 1
        return [_FakeProbabilities(self._probabilities) for _ in inputs]


class _FakeIocModule:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def scan_ioc(
        self,
        value: str,
        *,
        providers: dict[str, bool] | None = None,
        api_keys: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.calls.append(value)
        return {
            "ioc": value,
            "type": "ip" if value.count(".") == 3 else "domain",
            "status": "clean",
            "score": 10,
            "providers": {},
            "errors": [],
        }


class EntityExtractionTests(unittest.TestCase):
    def test_extracts_ip_domain_username_process_and_multiple_entities(self) -> None:
        log = (
            "timestamp=2026-04-04T12:00:00Z user=alice host=ws-01 process=powershell.exe "
            "src_ip=8.8.8.8 dst_ip=1.1.1.1 dns query for evil.example.com powershell -enc QUJD"
        )
        entities = _extract_entities(log, {})
        self.assertGreaterEqual(len(entities), 5)
        self.assertTrue(any(entity.type == "ipv4" and entity.value == "8.8.8.8" for entity in entities))
        self.assertTrue(any(entity.type == "ipv4" and entity.value == "1.1.1.1" for entity in entities))
        self.assertTrue(any(entity.type == "domain" and entity.value == "evil.example.com" for entity in entities))
        self.assertTrue(any(entity.type == "username" and entity.value == "alice" for entity in entities))
        self.assertTrue(any(entity.type == "process" and "powershell" in entity.value.lower() for entity in entities))

    def test_no_entity_case(self) -> None:
        entities = _extract_entities("completely benign message with no IOCs", {})
        self.assertEqual(entities, [])


class MitreRuleMappingTests(unittest.TestCase):
    def test_powershell_encoded_maps_to_t1059_with_rule_source(self) -> None:
        log = "user=alice process=powershell.exe command_line='powershell -enc QUJDRA=='"
        result = run(log)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1059")
        self.assertEqual(dump["audit"]["mapping_source"], "rule")

    def test_dns_tunnel_maps_to_t1071_with_rule_source(self) -> None:
        log = (
            "dns request aaaaaaaa.exfil.com "
            "dns request bbbbbbbb.exfil.com "
            "dns request cccccccc.exfil.com "
            "dns request dddddddd.exfil.com"
        )
        result = run(log)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1071")
        self.assertEqual(dump["audit"]["mapping_source"], "rule")

    def test_failed_login_bruteforce_maps_to_t1110_with_rule_source(self) -> None:
        log = (
            "failed login for user bob from 9.9.9.9; "
            "login failed again for user bob from 9.9.9.9; "
            "invalid password for account bob from 9.9.9.9"
        )
        result = run(log)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1110")
        self.assertEqual(dump["audit"]["mapping_source"], "rule")


class MlFallbackTests(unittest.TestCase):
    def test_no_rule_match_uses_ml_fallback_and_confidence(self) -> None:
        model = _FakeModel("T1059", [0.1, 0.9])
        result = run("routine event without deterministic signatures", model=model)
        dump = result.model_dump(mode="json")
        self.assertEqual(dump["attack_mapping"][0]["technique_id"], "T1059")
        self.assertEqual(dump["audit"]["mapping_source"], "ml_fallback")
        self.assertAlmostEqual(float(dump["attack_mapping"][0]["confidence"]), 0.9, places=6)
        self.assertEqual(model.predict_calls, 1)
        self.assertEqual(model.predict_proba_calls, 1)


class EpcOutputTests(unittest.TestCase):
    def test_epc_structure_and_non_empty_fields(self) -> None:
        result = run("powershell -enc QUJDRA==")
        dump = result.model_dump(mode="json")
        epc = dump["epc"]
        self.assertTrue(str(epc["explain"]).strip())
        self.assertTrue(isinstance(epc["plan"], list) and epc["plan"])
        self.assertTrue(isinstance(epc["checklist"], list) and epc["checklist"])
        self.assertTrue(all(str(item).strip() for item in epc["plan"]))
        self.assertTrue(all(str(item).strip() for item in epc["checklist"]))


class EnrichmentToggleTests(unittest.TestCase):
    def test_enrich_false_has_no_enrichment_section(self) -> None:
        result = run("process=powershell.exe command_line='powershell -enc QUJD'")
        dump = result.model_dump(mode="json")
        self.assertNotIn("ioc_enrichment", dump["audit"])

    def test_enrich_true_adds_deduped_ip_and_domain_only(self) -> None:
        fake = _FakeIocModule()
        log = (
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com process=powershell "
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com user=alice "
            "failed login user=alice src_ip=8.8.8.8 domain=evil.example.com"
        )
        with patch("src.pipeline._load_ioc_enrichment_module", return_value=fake):
            result = run(log, enrich_iocs=True)
        dump = result.model_dump(mode="json")
        enrichment = dump["audit"].get("ioc_enrichment", [])
        observed_iocs = [entry.get("ioc", "") for entry in enrichment]
        self.assertEqual(len(observed_iocs), 2)
        self.assertIn("8.8.8.8", observed_iocs)
        self.assertIn("evil.example.com", observed_iocs)
        self.assertNotIn("alice", observed_iocs)
        self.assertNotIn("powershell", observed_iocs)

    def test_enrich_iocs_direct_dedupes_duplicate_ip_and_domain_only(self) -> None:
        fake = _FakeIocModule()
        entities = [
            Entity(type="ipv4", value="8.8.8.8", evidence_ref="8.8.8.8"),
            Entity(type="ipv4", value="8.8.8.8", evidence_ref="8.8.8.8"),
            Entity(type="domain", value="evil.example.com", evidence_ref="evil.example.com"),
            Entity(type="domain", value="EVIL.EXAMPLE.COM", evidence_ref="EVIL.EXAMPLE.COM"),
            Entity(type="username", value="alice", evidence_ref="alice"),
            Entity(type="process", value="powershell.exe", evidence_ref="powershell.exe"),
            Entity(type="username", value="alice", evidence_ref="alice"),
        ]
        with patch("src.pipeline._load_ioc_enrichment_module", return_value=fake):
            enrichment = _enrich_iocs(entities)

        self.assertEqual(fake.calls, ["8.8.8.8", "evil.example.com"])
        self.assertEqual([item.get("ioc") for item in enrichment], ["8.8.8.8", "evil.example.com"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from pydantic import ValidationError

from src.evaluation import evaluate_classifier, evaluate_hybrid_pipeline
from src.model import load_model, save_model, train_attack_classifier
from src.pipeline import run


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOC Copilot CLI")
    parser.add_argument("raw_log", nargs="?", help="Raw log text to analyze")
    parser.add_argument("--model", dest="model_path", help="Path to a trained model file")
    parser.add_argument("--evaluate", dest="evaluate_path", help="Path to dataset JSONL for evaluation")
    parser.add_argument("--train", dest="train_path", help="Path to training dataset JSONL")
    parser.add_argument("--output-model", dest="output_model_path", help="Output path for trained model")
    parser.add_argument(
        "--enrich-iocs",
        action="store_true",
        help="Enable IOC enrichment for extracted IOC entities during inference.",
    )
    return parser


def _load_model(model_path: str | None) -> Any | None:
    if model_path is None:
        return None
    return load_model(model_path)


def _build_inference_output(
    raw_log: str, model: Any | None, *, enrich_iocs: bool = False
) -> dict[str, Any]:
    result = run(raw_log, model=model, enrich_iocs=enrich_iocs)
    mapping = result.attack_mapping[0]
    output: dict[str, Any] = {
        "technique_id": mapping.technique_id,
        "confidence": mapping.confidence,
        "mapping_source": result.audit.get("mapping_source"),
        "explain": result.epc.explain,
        "checklist": result.epc.checklist,
    }
    if enrich_iocs:
        output["ioc_enrichment"] = result.audit.get("ioc_enrichment", [])
    return output


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output: dict[str, Any] = {}
    model: Any | None = None

    if args.train_path is not None:
        if args.output_model_path is None:
            parser.error("--output-model PATH is required when using --train PATH.")
        trained_model = train_attack_classifier(args.train_path)
        save_model(trained_model, args.output_model_path)
        output["training"] = {
            "status": "ok",
            "dataset_path": args.train_path,
            "model_path": args.output_model_path,
        }

    if args.model_path is not None:
        model = _load_model(args.model_path)

    if args.raw_log is not None:
        try:
            output["result"] = _build_inference_output(
                args.raw_log,
                model=model,
                enrich_iocs=bool(args.enrich_iocs),
            )
        except ValidationError as exc:
            print(
                json.dumps(
                    {
                        "error": {
                            "type": "validation_error",
                            "message": "No ATT&CK mapping could be produced for the provided log.",
                            "details": exc.errors(),
                        }
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
    if args.evaluate_path is not None:
        evaluations: dict[str, Any] = {"classifier": evaluate_classifier(args.evaluate_path)}
        if model is not None:
            evaluations["hybrid"] = evaluate_hybrid_pipeline(args.evaluate_path, model=model)
        output["evaluation"] = evaluations

    if not output:
        parser.error("Provide raw_log and/or --evaluate PATH.")

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

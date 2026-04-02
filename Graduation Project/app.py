from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st
from pydantic import ValidationError

from src.evaluation import evaluate_classifier, evaluate_hybrid_pipeline
from src.model import load_model
from src.pipeline import run


def _read_uploaded_file(uploaded_file: Any) -> str:
    content = uploaded_file.read().decode("utf-8", errors="replace")
    if uploaded_file.name.lower().endswith(".json"):
        try:
            payload = json.loads(content)
            if isinstance(payload, dict) and isinstance(payload.get("raw_log"), str):
                return payload["raw_log"]
        except json.JSONDecodeError:
            pass
    return content


def _render_inference(raw_log: str, model: Any | None) -> None:
    try:
        result = run(raw_log, model=model)
    except ValidationError:
        st.error(
            "No deterministic ATT&CK rule matched and no ML fallback was available. "
            "Provide a trained model path or use a different log for detection."
        )
        return
    except Exception as exc:  # pragma: no cover - defensive UI guard
        st.error(f"Unexpected error while running pipeline: {exc}")
        return

    mapping = result.attack_mapping[0]

    st.subheader("Detection Result")
    st.json(
        {
            "technique_id": mapping.technique_id,
            "confidence": mapping.confidence,
            "mapping_source": result.audit.get("mapping_source"),
        }
    )

    st.subheader("Normalized Event")
    st.json(result.audit.get("normalized_event", {}))

    st.subheader("Extracted Entities")
    st.json([entity.model_dump(mode="json") for entity in result.entities])

    st.subheader("Attack Mapping")
    st.json([item.model_dump(mode="json") for item in result.attack_mapping])

    st.subheader("EPC")
    st.markdown(f"**Explain:** {result.epc.explain}")
    st.markdown("**Plan:**")
    for step in result.epc.plan:
        st.write(f"- {step}")
    st.markdown("**Checklist:**")
    for item in result.epc.checklist:
        st.write(f"- {item}")
    st.markdown(f"**Confidence:** {result.epc.confidence:.3f}")


def _render_evaluation(dataset_path: str, model: Any | None) -> None:
    if not dataset_path.strip():
        st.warning("Please provide a dataset path to run evaluation.")
        return

    try:
        classifier_metrics = evaluate_classifier(dataset_path)
        st.subheader("Classifier Evaluation")
        st.json(classifier_metrics)

        if model is not None:
            hybrid_metrics = evaluate_hybrid_pipeline(dataset_path, model=model)
            st.subheader("Hybrid Evaluation")
            st.json(hybrid_metrics)
    except Exception as exc:
        st.error(f"Evaluation failed: {exc}")


def main() -> None:
    st.set_page_config(page_title="SOC Copilot Demo", layout="wide")
    st.title("SOC Copilot Demo")
    st.caption("Rule-first ATT&CK mapping with optional ML fallback.")

    st.header("Inference")
    uploaded_file = st.file_uploader(
        "Optional log file upload (.txt or .json with raw_log)",
        type=["txt", "log", "json"],
    )
    raw_log_input = st.text_area("Raw log text", height=220)
    model_path = st.text_input("Optional trained model path")

    model = None
    if model_path.strip():
        try:
            model = load_model(model_path.strip())
            st.success("Model loaded successfully.")
        except Exception as exc:
            st.error(f"Could not load model: {exc}")

    selected_log = raw_log_input.strip()
    if uploaded_file is not None:
        uploaded_content = _read_uploaded_file(uploaded_file).strip()
        if uploaded_content:
            selected_log = uploaded_content

    if st.button("Run SOC Copilot", type="primary"):
        if not selected_log:
            st.warning("Please enter raw log text or upload a log file.")
        else:
            _render_inference(selected_log, model=model)

    st.divider()
    st.header("Evaluation")
    dataset_path = st.text_input("Dataset path (JSONL)", key="dataset_path")
    if st.button("Run Evaluation"):
        _render_evaluation(dataset_path, model=model)


if __name__ == "__main__":
    main()

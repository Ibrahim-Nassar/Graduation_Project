from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any

from src.dataset import ExportedTrainingRow


def train_attack_classifier(dataset_path: Path | str) -> Any:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    source_path = Path(dataset_path)
    texts: list[str] = []
    labels: list[str] = []

    for line in source_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        row = ExportedTrainingRow.model_validate(payload)
        texts.append(row.text)
        labels.append(row.technique_id)

    model = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    random_state=42,
                    solver="liblinear",
                ),
            ),
        ]
    )
    model.fit(texts, labels)
    return model


def predict_attack(text: str, model: Any) -> dict[str, Any]:
    predicted_label = str(model.predict([text])[0])
    probabilities = model.predict_proba([text])[0]
    top_index = int(probabilities.argmax())
    confidence = float(probabilities[top_index])

    return {"technique_id": predicted_label, "confidence": confidence}


def save_model(model: Any, path: Path | str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        pickle.dump(model, handle)


def load_model(path: Path | str) -> Any:
    input_path = Path(path)
    with input_path.open("rb") as handle:
        model = pickle.load(handle)

    predict = getattr(model, "predict", None)
    predict_proba = getattr(model, "predict_proba", None)
    if not callable(predict) or not callable(predict_proba):
        raise ValueError("Loaded object is not a compatible classifier pipeline")

    return model

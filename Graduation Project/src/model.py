from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

def predict_attack(text: str, model: Any) -> dict[str, Any]:
    predicted_label = str(model.predict([text])[0])
    probabilities = model.predict_proba([text])[0]
    top_index = int(probabilities.argmax())
    confidence = float(probabilities[top_index])

    return {"technique_id": predicted_label, "confidence": confidence}


def load_model(path: Path | str) -> Any:
    input_path = Path(path)
    with input_path.open("rb") as handle:
        model = pickle.load(handle)

    predict = getattr(model, "predict", None)
    predict_proba = getattr(model, "predict_proba", None)
    if not callable(predict) or not callable(predict_proba):
        raise ValueError("Loaded object is not a compatible classifier pipeline")

    return model

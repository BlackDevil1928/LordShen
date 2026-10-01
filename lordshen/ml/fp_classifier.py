"""Random Forest false positive classifier for vulnerability findings."""

import json
import pickle
from pathlib import Path
from typing import Any

from lordshen.core.config import CONFIG_DIR
from lordshen.core.console import print_info, print_warning

MODEL_PATH = CONFIG_DIR / "models" / "fp_model.pkl"
SEED_DATA_PATH = Path(__file__).parent / "seed_data.json"


class FPClassifier:
    """ML-based false positive classifier using scikit-learn Random Forest."""

    def __init__(self) -> None:
        self.model: Any = None
        self.vectorizer: Any = None
        self._load_or_train()

    def _load_or_train(self) -> None:
        """Load saved model or train from seed data."""
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                    self.model = saved["model"]
                    self.vectorizer = saved["vectorizer"]
                return
            except Exception:
                pass

        self._train()

    def _train(self) -> None:
        """Train model from seed_data.json."""
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.pipeline import Pipeline
        except ImportError:
            print_warning("scikit-learn not installed. FP classifier disabled.")
            return

        if not SEED_DATA_PATH.exists():
            print_warning("No seed data found for FP classifier training.")
            return

        try:
            data = json.loads(SEED_DATA_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return

        if len(data) < 10:
            return

        texts = []
        labels = []
        for item in data:
            feature_text = (
                f"{item.get('tool', '')} {item.get('title', '')} "
                f"{item.get('severity', '')} {item.get('evidence', '')}"
            )
            texts.append(feature_text)
            labels.append(1 if item.get("is_fp", False) else 0)

        self.vectorizer = TfidfVectorizer(max_features=500, stop_words="english")
        X = self.vectorizer.fit_transform(texts)

        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, labels)

        # Save model
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"model": self.model, "vectorizer": self.vectorizer}, f)

    def predict(self, finding: dict[str, Any]) -> tuple[bool, float]:
        """Predict if a finding is a false positive.

        Returns:
            Tuple of (is_false_positive, confidence 0-1).
        """
        if self.model is None or self.vectorizer is None:
            return False, 0.0

        text = (
            f"{finding.get('tool_name', '')} {finding.get('title', '')} "
            f"{finding.get('severity', '')} {finding.get('evidence', '')}"
        )

        X = self.vectorizer.transform([text])
        proba = self.model.predict_proba(X)[0]
        is_fp = bool(proba[1] > 0.6)  # Threshold at 60%
        confidence = float(max(proba))

        return is_fp, confidence

    def batch_predict(self, findings: list[dict[str, Any]]) -> list[tuple[bool, float]]:
        """Predict FP for multiple findings."""
        return [self.predict(f) for f in findings]

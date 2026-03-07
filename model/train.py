
import argparse
from dataclasses import dataclass
from typing import Dict, Any

import numpy as np
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)
from datasets import Dataset, DatasetDict
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

from utils.seed import set_seed
from utils.data_utils import load_toy_dataset
from app.features import quick_engineered_features


@dataclass
class Example:
    subject: str
    body: str
    label: int
    headers: Dict[str, Any]


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="binary", zero_division=0),
    }


def build_dataset(tokenizer, max_length: int, use_hybrid: bool):
    examples = load_toy_dataset()
    texts = [f"Subject: {e.subject}\n\n{e.body}" for e in examples]
    labels = [e.label for e in examples]

    tok = tokenizer(texts, truncation=True, padding=True, max_length=max_length)

    if use_hybrid:
        feats = [quick_engineered_features(e.subject, e.body, e.headers) for e in examples]
        tok["engineered"] = feats  # placeholder: not wired into model in MVP

    data = {**tok, "labels": labels}
    dataset = Dataset.from_dict(data)

    idx = list(range(len(labels)))
    train_idx, test_idx = train_test_split(
        idx, test_size=0.25, random_state=42, stratify=labels
    )
    return DatasetDict({"train": dataset.select(train_idx), "test": dataset.select(test_idx)})


class HybridTrainer(Trainer):
    """Strips the 'engineered' feature column before the model forward pass."""

    def compute_loss(self, model, inputs, return_outputs=False, **_kwargs):
        inputs = {k: v for k, v in inputs.items() if k != "engineered"}
        outputs = model(**inputs)
        loss = outputs.loss
        return (loss, outputs) if return_outputs else loss


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="model/config.yaml")
    args = parser.parse_args()

    import yaml
    cfg = yaml.safe_load(open(args.config, encoding="utf-8"))

    set_seed(cfg.get("seed", 42))

    model_name = cfg["model_name"]
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    dataset = build_dataset(tokenizer, cfg["max_length"], cfg.get("use_hybrid_head", True))

    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)

    training_args = TrainingArguments(
        output_dir=cfg["output_dir"],
        learning_rate=cfg["lr"],
        per_device_train_batch_size=cfg["train_batch_size"],
        per_device_eval_batch_size=cfg["eval_batch_size"],
        num_train_epochs=cfg["epochs"],
        weight_decay=cfg["weight_decay"],
        warmup_ratio=cfg.get("warmup_ratio", 0.06),
        gradient_accumulation_steps=cfg.get("grad_accum_steps", 1),
        eval_strategy="epoch",   # replaces deprecated evaluation_strategy
        save_strategy="epoch",
        logging_steps=20,
        report_to=[],
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
    )

    trainer = HybridTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["test"],
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    trainer.save_model(cfg["output_dir"])
    tokenizer.save_pretrained(cfg["output_dir"])
    print("Training complete. Artifacts saved to", cfg["output_dir"])


if __name__ == "__main__":
    main()

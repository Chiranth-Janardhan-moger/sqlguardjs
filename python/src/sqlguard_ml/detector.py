import json
import pickle
import os
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

class AttentionLayer(layers.Layer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def call(self, x):
        score = tf.nn.softmax(tf.reduce_sum(x, axis=2), axis=1)
        score = tf.expand_dims(score, axis=2)
        context = x * score
        return tf.reduce_sum(context, axis=1)

    def get_config(self):
        cfg = super().get_config()
        return cfg

class PayloadDetector:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.le = None
        self.max_sequence_length = 120
        self.models_dir = os.path.join(os.path.dirname(__file__), "models")

    def _load_artifacts(self):
        if self.model is not None:
            return

        model_path = os.path.join(self.models_dir, "attack_cnn_lstm.h5")
        tokenizer_path = os.path.join(self.models_dir, "tokenizer.json")
        le_path = os.path.join(self.models_dir, "label_encoder.pkl")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at {model_path}")
        if not os.path.exists(tokenizer_path):
            raise FileNotFoundError(f"Tokenizer not found at {tokenizer_path}")
        if not os.path.exists(le_path):
            raise FileNotFoundError(f"Label encoder not found at {le_path}")

        self.model = tf.keras.models.load_model(
            model_path, custom_objects={"AttentionLayer": AttentionLayer}
        )

        with open(tokenizer_path, "r", encoding="utf-8") as f:
            self.tokenizer = tokenizer_from_json(f.read())

        with open(le_path, "rb") as f:
            self.le = pickle.load(f)

    def predict(self, text: str) -> dict:
        """
        Predict attack type for a payload.
        Returns a dict with 'label' and 'confidence'.
        """
        self._load_artifacts()
        
        seq = self.tokenizer.texts_to_sequences([text])
        pad = pad_sequences(
            seq, maxlen=self.max_sequence_length, padding="post", truncating="post"
        )
        probs = self.model.predict(pad, verbose=0)
        
        pred_idx = int(np.argmax(probs, axis=1)[0])
        confidence = float(np.max(probs, axis=1)[0])
        label = self.le.classes_[pred_idx]
        
        return {
            "label": label,
            "confidence": confidence,
            "probabilities": probs[0].tolist()
        }

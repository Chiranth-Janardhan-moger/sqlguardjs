import json
from pathlib import Path
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json

# --- EXACT COPY of AttentionLayer from train_model.py ---
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

# --- paths & constants ---
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "attack_cnn_lstm.h5"
TOKENIZER_PATH = BASE_DIR / "tokenizer.json"
LABEL_ENCODER_PATH = BASE_DIR / "label_encoder.json"
MAX_SEQUENCE_LENGTH = 120  # match training

model = None
tokenizer = None
le = None

def load_artifacts():
    global model, tokenizer, le
    if model is not None:
        return

    model = tf.keras.models.load_model(MODEL_PATH, custom_objects={"AttentionLayer": AttentionLayer})

    with open(TOKENIZER_PATH, "r", encoding="utf-8") as f:
        tokenizer_json = f.read()
    tokenizer = tokenizer_from_json(tokenizer_json)

    with open(LABEL_ENCODER_PATH, "r", encoding="utf-8") as f:
        le = np.array(json.load(f))

def predict_payload(text: str) -> str:
    """Predict attack type for a payload"""
    load_artifacts()
    seq = tokenizer.texts_to_sequences([text])
    pad = pad_sequences(seq, maxlen=MAX_SEQUENCE_LENGTH, padding="post", truncating="post")
    probs = model.predict(pad, verbose=0)
    pred = int(np.argmax(probs, axis=1)[0])
    return le[pred]

if __name__ == "__main__":
    print("Test 1", predict_payload("' OR '1"))

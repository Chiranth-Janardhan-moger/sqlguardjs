# SQLGuardJS: Model Training & Prediction

## How to run it

Open a terminal in the project root:
```bash
cd sqlguardjs/python
```

Install the required Python packages:
```bash
pip install -e .
```

The API verifies shipped model artifact hashes before loading. If required artifacts
are missing or modified, `/health` and `/api/v1/detect` return `503` instead of
classifying requests as benign.

For dataset regeneration or model training helpers:
```bash
pip install -e .[dataset]
```

### Train the model:
```bash
cd dataset
python train_model.py --fast
```

This will read `payload_dataset1.csv`, train the neural network, and save the following artifacts:
- `attack_cnn_lstm.h5`
- `tokenizer.json`
- `label_encoder.json`

### Run prediction locally:
```bash
python predict.py
```

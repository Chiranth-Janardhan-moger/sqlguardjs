# SQLGuardjs: Model Training & Prediction

## How to run it

Open a terminal in the project root:
```bash
cd sqlguard-ml/python
```

Install the required Python packages:
```bash
pip install tensorflow pandas scikit-learn numpy
```

### Train the model:
```bash
cd dataset
python train_model.py --fast
```

This will read `payload_dataset1.csv`, train the neural network, and save the following artifacts:
- `attack_cnn_lstm.h5`
- `tokenizer.json`
- `label_encoder.pkl`

### Run prediction locally:
```bash
python predict.py
```

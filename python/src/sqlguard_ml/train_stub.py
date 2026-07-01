import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

def train_and_save():
    # Simple synthetic dataset
    data = [
        "SELECT * FROM users", # benign in context (often internal query, but let's train on obvious)
        "admin' --",           # sqli
        "1; DROP TABLE users", # sqli
        "<script>alert(1)</script>", # xss
        "hello world",         # benign
        "UNION SELECT",        # sqli
        "javascript:alert(1)", # xss
        "just a normal text",  # benign
        "O'Brien",             # benign
    ]
    labels = ["benign", "sqli", "sqli", "xss", "benign", "sqli", "xss", "benign", "benign"]

    # Use character n-grams
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3))
    X = vectorizer.fit_transform(data)

    model = LogisticRegression(max_iter=100)
    model.fit(X, labels)

    base_path = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_path, 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    joblib.dump(vectorizer, os.path.join(models_dir, 'stub_vectorizer.pkl'))
    joblib.dump(model, os.path.join(models_dir, 'stub_model.pkl'))
    
    print("Stub model trained and saved successfully.")

if __name__ == '__main__':
    train_and_save()

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

password_lengths = np.random.randint(5, 16, 200)  # Weak: 5-15 chars
strong_lengths = np.random.randint(16, 40, 200)  # Strong: 16-40 chars
data = np.concatenate((password_lengths, strong_lengths)).reshape(-1, 1)

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(data)

joblib.dump(model, "password_anomaly_detector.pkl")
print("Model saved as password_anomaly_detector.pkl")

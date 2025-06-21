import hashlib
import json
import random
import string
import bcrypt
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import base64
import os
import joblib
import rsa
from bcrypt import gensalt, hashpw, checkpw
from utils.bcrpyt import check_password_strength, hash_password
from utils.key_exchange import compute_public_key, compute_shared_secret
from utils.encryption import Encryptor
from utils.signature import DigitalSignature
from cryptography.fernet import Fernet
import numpy as np
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template("index.html")



normal_hashes = [
    "5d41402abc4b2a76b9719d911017c592", "3b9d5e08eb47b63c63d6b3a5b4713bd4",
    "9a3b68b2f5e142da93f5f72d1a8c32a1", "87f14f3a5b7b41b18d5d4f2a713b1a5f"
]
X_train = np.array([[int(h[:4], 16)] for h in normal_hashes])  # Convert first 4 hex digits to numbers

# Train Isolation Forest model
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)

def generate_hash(text):
    """Generate SHA-256 hash from text"""
    return hashlib.sha256(text.encode()).hexdigest()

def detect_anomaly(hash_value):
    """AI-powered anomaly detection"""
    hash_numeric = int(hash_value[:4], 16)  # Convert first 4 hex digits to a number
    score = model.decision_function([[hash_numeric]])[0]  # AI anomaly score
    anomaly = model.predict([[hash_numeric]])[0] == -1  # Detect anomaly

    return anomaly, round(score, 2)  # Return result + confidence score

def self_heal_text(text):
    """Modify input text and regenerate hash for self-healing"""
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    healed_text = text + salt
    return healed_text, generate_hash(healed_text)

@app.route("/hashing", methods=["GET", "POST"])
def hash_generator():
    if request.method == "POST":
        input_text = request.form["text"]
        generated_hash = generate_hash(input_text)

        # AI anomaly detection
        anomaly_detected, confidence_score = detect_anomaly(generated_hash)

        if anomaly_detected:
            healed_text, healed_hash = self_heal_text(input_text)
            return render_template(
                "hash.html",
                input_text=input_text,
                generated_hash=generated_hash,
                status=f"🚨 Anomaly Detected! (AI Score: {confidence_score})",
                healed_text=healed_text,
                healed_hash=healed_hash
            )

        return render_template(
            "hash.html",
            input_text=input_text,
            generated_hash=generated_hash,
            status=f"✅ Hash is Normal (AI Score: {confidence_score})",
            confidence_score=confidence_score  # Pass AI score explicitly
        )


    return render_template("hash.html")



@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_decrypt():
    encrypted_text = None
    decrypted_text = None

    if request.method == "POST":
        message = request.form.get("message")
        password = request.form.get("password")
        action = request.form.get("action")

        if not message or not password:
            return render_template("encrypt.html", error="Both fields are required")

        encryptor = Encryptor(password)

        if action == "encrypt":
            result = encryptor.encrypt_message(message)
            encrypted_text = f"{result['iv']}:{result['ciphertext']}"
        elif action == "decrypt":
            try:
                iv, ct = message.split(":")
                decrypted_text = encryptor.decrypt_message(iv, ct)
            except Exception as e:
                return render_template("encrypt.html", error="Invalid encrypted text format")

    return render_template("encrypt.html", encrypted_text=encrypted_text, decrypted_text=decrypted_text)


@app.route("/sign", methods=["GET", "POST"])
def sign_message():
    if request.method == "GET":
        return render_template("sign.html")

    message = request.form.get("message")

    if not message:
        return render_template("sign.html", error="Message is required")

    signer = DigitalSignature()
    signature, public_key = signer.generate_signature(message)

    return render_template("sign.html", signed_message=signature, public_key=public_key)

@app.route("/verify", methods=["POST"])
def verify_message():
    message = request.form.get("message")
    signature = request.form.get("signature")
    public_key = request.form.get("public_key")

    if not message or not signature or not public_key:
        return render_template("sign.html", error="All fields are required for verification")

    verifier = DigitalSignature()
    is_valid = verifier.verify_signature(message, signature, public_key)

    return render_template("sign.html", is_valid=is_valid)



def compute_public_key(P, G, private_key):
    return (G ** private_key) % P

def compute_shared_secret(P, public_key, private_key):
    return (public_key ** private_key) % P

@app.route("/key_exchange", methods=["GET", "POST"])
def key_exchange():
    if request.method == "POST":
        try:
            P = int(request.form["prime"])
            G = int(request.form["generator"])
            a = int(request.form["private_a"])
            b = int(request.form["private_b"])

            A = compute_public_key(P, G, a)
            B = compute_public_key(P, G, b)

            shared_secret_A = compute_shared_secret(P, B, a)
            shared_secret_B = compute_shared_secret(P, A, b)

            return render_template("key_exchange.html", P=P, G=G, a=a, b=b, A=A, B=B, 
                                shared_secret_A=shared_secret_A, shared_secret_B=shared_secret_B)

        except Exception as e:
            return render_template("key_exchange.html", error=str(e))

    return render_template("key_exchange.html")



MODEL_PATH = "password_anomaly_detector.pkl"
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
else:
    model = None  # Prevent error if model is missing
@app.route("/bcrypt")
def bcrypt():
    return render_template("bcrypt.html")

@app.route("/generate_hash2", methods=["POST"])
def generate_hash2():
    text = request.form["text"]
    rounds = int(request.form["rounds"])w
    salt = gensalt(rounds=rounds)
    hashed_text = hashpw(text.encode(), salt).decode()
    return jsonify({"hashed_text": hashed_text})

@app.route("/verify_hash", methods=["POST"])
def verify_hash():
    text = request.form["text"]
    hashed_text = request.form["hash"]
    is_valid = checkpw(text.encode(), hashed_text.encode())
    return jsonify({"valid": is_valid})

 


model = joblib.load("password_anomaly_detector.pkl")

@app.route("/bcrypt_page", methods=["GET", "POST"])
def bcrypt_page():
    hashed_password = None
    strength_message = None

    if request.method == "POST":
        password = request.form["password"]
        hashed_password = hash_password(password)
        strength_message = check_password_strength(password)

    return render_template("bcrypt.html", hashed_password=hashed_password, strength_message=strength_message)


if __name__ == "__main__":
    app.run(debug=True)

import re
import bcrypt
import joblib 

def generate_bcrypt_hash(text, rounds):
    """Generate a bcrypt hash for the given text."""
    salt = bcrypt.gensalt(rounds=rounds)
    hashed_text = bcrypt.hashpw(text.encode(), salt)
    return hashed_text.decode()

def verify_bcrypt_hash(text, hashed_text):
    """Verify if the given text matches the bcrypt hash."""
    return bcrypt.checkpw(text.encode(), hashed_text.encode())
import re
import bcrypt
import joblib

# Load AI Model Globally
try:
    model = joblib.load("password_anomaly_detector.pkl")  # 🔥 Ensure this file exists in the correct directory
except FileNotFoundError:
    model = None  # If model is missing, set to None

def generate_bcrypt_hash(text, rounds):
    """Generate a bcrypt hash for the given text."""
    salt = bcrypt.gensalt(rounds=rounds)
    hashed_text = bcrypt.hashpw(text.encode(), salt)
    return hashed_text.decode()

def verify_bcrypt_hash(text, hashed_text):
    """Verify if the given text matches the bcrypt hash."""
    return bcrypt.checkpw(text.encode(), hashed_text.encode())

def hash_password(password):
    """Hashes the password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password_strength(password):
    """Uses AI + manual rules to determine password strength."""
    global model  # ✅ Ensure model is accessible in this function
    length = len(password)

    # Check complexity: Upper, lower, digit, special char
    complexity_score = sum([
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[0-9]', password)),
        bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    ])

    # Check AI-based strength
    if model:  
        ai_score = -model.decision_function([[length]])[0]  # Ensure the model exists
    else:
        ai_score = 0  # Default if no model is loaded

    # Define Strength Conditions
    if length < 8 or complexity_score < 2:
        return "❌ Weak Password"
    elif length < 12 or complexity_score == 2:
        return "⚠️ Moderate Password"
    elif ai_score > 0.6:  # AI detects anomaly
        return "🚨 Suspicious Password (May be weak!)"
    else:
        return "✅ Strong Password"

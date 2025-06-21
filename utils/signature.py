import ecdsa
import base64

class DigitalSignature:
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def generate_signature(self, message):
        """Signs a message and returns the signature and public key."""
        signature = self.private_key.sign(message.encode())
        return base64.b64encode(signature).decode(), base64.b64encode(self.public_key.to_string()).decode()

    def verify_signature(self, message, signature, public_key):
        """Verifies a given signature using the provided public key."""
        try:
            public_key_bytes = base64.b64decode(public_key)
            signature_bytes = base64.b64decode(signature)

            vk = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=ecdsa.SECP256k1)
            return vk.verify(signature_bytes, message.encode())
        except Exception:
            return False

def compute_public_key(P, G, private_key):
    """Compute the public key using Diffie-Hellman formula."""
    return pow(G, private_key, P)

def compute_shared_secret(P, public_key, private_key):
    """Compute the shared secret key."""
    return pow(public_key, private_key, P)

if __name__ == "__main__":
    P = int(input("Enter a prime number (P): "))
    G = int(input("Enter a generator number (G): "))
    a = int(input("Enter Private Key for User A: "))
    b = int(input("Enter Private Key for User B: "))

    A = compute_public_key(P, G, a)  # Public Key for A
    B = compute_public_key(P, G, b)  # Public Key for B

    shared_secret_A = compute_shared_secret(P, B, a)
    shared_secret_B = compute_shared_secret(P, A, b)

    print(f"\nPublic Key A: {A}")
    print(f"Public Key B: {B}")
    print(f"Shared Secret (A's side): {shared_secret_A}")
    print(f"Shared Secret (B's side): {shared_secret_B}")

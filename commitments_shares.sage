import random
import hashlib
from sage.all import GF

p = 101
F = GF(p)

def secret_share(value):
    share1 = F(random.randint(0, p - 1))
    share2 = F(random.randint(0, p - 1))
    share3 = F((value - share1 - share2) % p)
    return [share1, share2, share3]

def commit(share):
    return hashlib.sha256(",".join(map(str, share)).encode()).hexdigest()

def secret_sharing_with_commitments(value):
    shares = secret_share(value)
    commitments = [commit([share]) for share in shares]
    return shares, commitments

def test_secret_sharing_with_commitments():
    value = F(42)

    # Prover generates shares and commitments
    shares, commitments = secret_sharing_with_commitments(value)

    print("Original value:", value)
    print("Shares:", shares)
    print("Commitments:", commitments)

    # Verifier checks reconstruction
    reconstructed = sum(shares) % p
    print("Reconstructed value:", reconstructed)
    assert reconstructed == value, "Reconstruction failed!"

    # Verify commitment
    for i, share in enumerate(shares):
        assert commit([share]) == commitments[i], f"Commitment mismatch for share {i}!"

    print("Secret sharing with commitments passed!")

if __name__ == "__main__":
    test_secret_sharing_with_commitments()

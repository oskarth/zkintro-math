import random
import hashlib
from sage.all import GF

# Global setup
p = 101  # Prime for GF(p)
F = GF(p)  # Finite field

# Secret Sharing
def secret_share(value):
    share1 = F(random.randint(0, p - 1))
    share2 = F(random.randint(0, p - 1))
    share3 = F((value - share1 - share2) % p)
    return [share1, share2, share3]

# Commitments
def commit(share):
    return hashlib.sha256(",".join(map(str, share)).encode()).hexdigest()

# ZKBoo Prover
def zkboo_prover(c, d):
    c_shares = secret_share(c)
    d_shares = secret_share(d)
    e_shares = [(c_shares[i] + d_shares[i]) % p for i in range(3)]
    commitments = [commit((c_shares[i], d_shares[i], e_shares[i])) for i in range(3)]
    return c_shares, d_shares, e_shares, commitments

# Verifier Challenge
def zkboo_verifier_challenge():
    return random.sample([0, 1, 2], 2)

# Prover Response
def zkboo_prover_response(challenge, c_shares, d_shares, e_shares):
    return [{'c': c_shares[i], 'd': d_shares[i], 'e': e_shares[i]} for i in challenge]

# Verifier
def zkboo_verify(challenge, response, commitments):
    for i, col in enumerate(challenge):
        if commit((response[i]['c'], response[i]['d'], response[i]['e'])) != commitments[col]:
            return False
    return all((share['c'] + share['d']) % p == share['e'] for share in response)

# Test Cases
def test_zkboo():
    c, d = F(7), F(3)
    c_shares, d_shares, e_shares, commitments = zkboo_prover(c, d)
    challenge = zkboo_verifier_challenge()
    response = zkboo_prover_response(challenge, c_shares, d_shares, e_shares)
    assert zkboo_verify(challenge, response, commitments), "ZKBoo addition test failed"
    print("Test passed!")

# Run Tests
if __name__ == "__main__":
    test_zkboo()

import random, hashlib
from sage.all import GF

p = 101
F = GF(p)

def secret_share(value):
    """Split 'value' into 3 random shares mod p."""
    s1, s2 = F.random_element(), F.random_element()
    return [s1, s2, (value - s1 - s2) % p]

def commit(vals):
    """Hash tuple of values to produce a commitment."""
    return hashlib.sha256(",".join(map(str, vals)).encode()).hexdigest()

def multiply_shares(a_sh, b_sh):
    """Compute c_i for a single gate a*b=c with offsets r_i."""
    r = [F.random_element() for _ in range(3)]
    c = [(a_sh[i] * b_sh[i] + a_sh[i] * b_sh[(i + 1) % 3] + a_sh[(i + 1) % 3] * b_sh[i] + r[i] - r[(i + 1) % 3]) % p for i in range(3)]
    assert sum(c) % p == (sum(a_sh) * sum(b_sh)) % p
    return c, r

def zkboo_prover(a, b, d):
    """Generate shares for a,b,d and compute c=a*b, e=c+d with random offsets."""
    a_sh, b_sh, d_sh = secret_share(a), secret_share(b), secret_share(d)
    c_sh, r_sh = multiply_shares(a_sh, b_sh)
    e_sh = [(c_sh[i] + d_sh[i]) % p for i in range(3)]
    commits = [commit((a_sh[i], b_sh[i], c_sh[i], d_sh[i], e_sh[i], r_sh[i])) for i in range(3)]
    return a_sh, b_sh, c_sh, d_sh, e_sh, commits, r_sh

def zkboo_verifier_challenge():
    """Pick two random shares to reveal."""
    return random.sample(range(3), 2)

def zkboo_prover_response(ch, a_sh, b_sh, c_sh, d_sh, e_sh, r_sh):
    """Reveal the requested two shares with all data."""
    return [{"a": a_sh[i], "b": b_sh[i], "c": c_sh[i], "d": d_sh[i], "e": e_sh[i], "r": r_sh[i]} for i in ch]

def zkboo_verify(ch, resp, commits):
    """Check commitments and verify correctness of revealed shares."""
    if any(commit((resp[i]["a"], resp[i]["b"], resp[i]["c"], resp[i]["d"], resp[i]["e"], resp[i]["r"])) != commits[ch[i]] for i in range(2)):
        return False
    def check_c(sh_i, sh_j):
        return (sh_i["a"] * sh_i["b"] + sh_i["a"] * sh_j["b"] + sh_j["a"] * sh_i["b"] + (sh_i["r"] - sh_j["r"])) % p == sh_i["c"]
    # Ensure correct pairs of shares are used when verifying multiplication consistency
    if (ch[0] + 1) % 3 == ch[1] and not check_c(resp[0], resp[1]): return False
    if (ch[1] + 1) % 3 == ch[0] and not check_c(resp[1], resp[0]): return False
    return all((share["c"] + share["d"]) % p == share["e"] for share in resp)

def test_zkboo_single_round():
    """Test a single-round reveal for a,b,d = 3,4,5."""
    a, b, d = F(3), F(4), F(5)
    a_sh, b_sh, c_sh, d_sh, e_sh, commits, r_sh = zkboo_prover(a, b, d)
    ch = zkboo_verifier_challenge()
    resp = zkboo_prover_response(ch, a_sh, b_sh, c_sh, d_sh, e_sh, r_sh)
    assert zkboo_verify(ch, resp, commits), "ZKBoo single-round failed"
    print("Single-round test passed!")

test_zkboo_single_round()

# KEM.py
# SIKE Algorithm 2 (KeyGen, Encaps, Decaps) built on PKE.

from secrets import token_bytes, randbelow
from hashlib import shake_256
from math import ceil
from typing import Optional, Tuple

from PKE import SIKEParams, Gen, Enc, Dec
from IsogenyAlgs.IsogenAlgorithm import compute_public_key_isogeny


Fp2 = Tuple[int, int]
Pk2 = Tuple[Fp2, Fp2, Fp2]

# This function calculates how many bytes are needed to store any number modulo p.
def _nbytes_p(p: int) -> int:
    return ceil(p.bit_length() / 8)

# This function takes an element x of the quadratic extension field Fp² represented as a pair (a,b), where both a and b are 
# integers mod p. It converts each coordinate into a fixed-length big-endian byte string and concatenates them.
def _ser_fp2(x: Fp2, p: int) -> bytes:
    a, b = x
    n = _nbytes_p(p)
    return (a % p).to_bytes(n, "big") + (b % p).to_bytes(n, "big")

# This function serializes a public key pk, and returns the binary encoding of all three of its x-coordinates concatenated together.
def _ser_pk(pk: Pk2, p: int) -> bytes:
    xP, xQ, xR = pk
    return _ser_fp2(xP, p) + _ser_fp2(xQ, p) + _ser_fp2(xR, p)

# This function serializes a ciphertext (c0, c1), where c0 is a public key and c1 is a byte string.
def _ser_ct(c0: Pk2, c1: bytes, p: int) -> bytes:
    return _ser_pk(c0, p) + c1


# ---------- KDF-like helpers G and H ----------

# This function derives an integer r in [0, 2^e2) from the concatenation of a message m and a public key pk3, using SHAKE-256.
def _G(m_and_pk3: bytes, e2: int) -> int:
    """r in [0, 2^e2) derived from SHAKE-256(m || pk3)."""
    outlen = ceil(e2 / 8)
    r = int.from_bytes(shake_256(m_and_pk3).digest(outlen), "big")
    return r % (1 << e2)

# This function derives a shared secret K from input data by hashing it with SHAKE-256.
def _H(data: bytes, outlen: int = 32) -> bytes:
    """K = SHAKE-256(data, outlen)."""
    return shake_256(data).digest(outlen)


# ---------- KEM ----------

def KeyGen(params: SIKEParams):
    """Return (s, sk3, pk3)."""
   
    (P2, Q2, R2), (P3, Q3, _) = params.bases()
    xP2, xQ2, xR2 = P2[0], Q2[0], R2[0]

    # 1) sk_3 <–– Random in K_3 = [0, 3^e3)
    sk3 = randbelow(pow(3, params.e3))

    # 2) pk3 <–– isogen_3(sk_3)
    pk3 = compute_public_key_isogeny(
        p        = params.p,
        l        = 3,
        e_l      = params.e3,
        sk_l     = sk3,
        A_start  = params.A0,
        P_l      = P3,
        Q_l      = Q3,
        xP_m     = xP2,
        xQ_m     = xQ2,
        xR_m     = xR2,
    )

    # 3) s <–– random n-bit string (here 256b)
    s = token_bytes(32)

    # 4) return (s, sk3, pk3)        
    return s, sk3, pk3

def Encaps(params: SIKEParams, pk3: Pk2):
    """Return ((c0, c1), K)."""

    # 5) m <–– random n-bit message (here 256b)
    m = token_bytes(32)

    # 6) r <–– G(m || pk3)
    r = _G(m + _ser_pk(pk3, params.p), params.e2)

    print("ENC m =", m.hex())
    print("ENC r =", r)

    # 7) (c0, c1) <–– Enc(pk3, m, r)
    c0, c1 = Enc(params, pk3, m, r) 

    # 8) K <–– H(m || (c0,c1))    
    K = _H(m + _ser_ct(c0, c1, params.p))    

    # 9) return ((c0, c1), K)
    return (c0, c1), K

def Decaps(params: SIKEParams, s: bytes, sk3: int, pk3: Pk2, ciphertext):
    """Return K."""
    c0, c1 = ciphertext

    # 10) m' <–– Dec(sk3, (c0, c1))
    m_prime = Dec(params, sk3, (c0, c1))

    # 11) r' <–– G(m' || pk3)
    r_prime = _G(m_prime + _ser_pk(pk3, params.p), params.e2)

    print("DEC m' =", m_prime.hex() if isinstance(m_prime, (bytes, bytearray)) else m_prime)
    print("DEC r' =", r_prime)

    # 12) c0' = isogen2(r')
    (P2, Q2, _), (P3, Q3, R3) = params.bases()
    xP3, xQ3, xR3 = P3[0], Q3[0], R3[0]
    c0_prime = compute_public_key_isogeny(
        p       = params.p,
        l       = 2,
        e_l     = params.e2,
        sk_l    = r_prime,
        A_start = params.A0,
        P_l     = P2,
        Q_l     = Q2,
        xP_m    = xP3,
        xQ_m    = xQ3,
        xR_m    = xR3,
    )
    # 13) if c0' == c0 then 
    ct_bytes = _ser_ct(c0, c1, params.p)
    print("Checking if C0' equals C0...")
    if c0_prime == c0:
        # 14) K <–– H(m' || (c0, c1))
        K = _H(m_prime + ct_bytes)   # good ciphertext
    # 15) else   
    else:
        # 16) K <–– H(s || (c0, c1))
        K = _H(s + ct_bytes)         # fallback per Algorithm 2
        print("ERRRRR0OOOOOOOR")
    # 17) return K
    return K


# ---------- demo ----------

if __name__ == "__main__":
    # same toy params as your PKE demo
    p = 647
    A0 = (6 % p, 0)
    e2, e3 = 3, 4
    params = SIKEParams(p=p, A0=A0, e2=e2, e3=e3)

    print("[+] KEM demo start")
    s, sk3, pk3 = KeyGen(params)
    (c0, c1), K_enc = Encaps(params, pk3)
    K_dec = Decaps(params, s, sk3, pk3, (c0, c1))
    print("K_enc =", K_enc.hex())
    print("K_dec =", K_dec.hex())
    assert K_enc == K_dec, "key mismatch!"
    print("keys match")

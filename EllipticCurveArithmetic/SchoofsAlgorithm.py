# SchoofsAlgorithm.py
# Run with: sage -python SchoofsAlgorithm.py

from sage.all import (
    GF, PolynomialRing, EllipticCurve,
    next_prime, Integer, sqrt
)

def sike_fp2_field(p: int):
    Fp = GF(p)
    R = PolynomialRing(Fp, names=("u",))
    (u,) = R.gens()
    Fp2 = GF(p**2, name="i", modulus=u**2 + 1)
    return Fp2

def montgomery_curve_as_weierstrass(F, A, B=1):
    if B != 1:
        raise NotImplementedError("This script assumes B=1 (the usual SIKE convention).")
    a1 = F(0)
    a3 = F(0)
    a2 = F(A)
    a4 = F(1)
    a6 = F(0)
    return EllipticCurve(F, [a1, a2, a3, a4, a6])

def trace_of_frobenius(E) -> int:
    """
    Frobenius trace t = q + 1 - #E(F_q).
    Sage computes #E(F_q) efficiently (Schoof/SEA methods internally).
    """
    F = E.base_field()
    q = Integer(F.order())
    N = Integer(E.cardinality())
    return Integer(q + 1 - N)

def crt_update(t_mod_M: int, M: int, t_mod_l: int, l: int):
    """
    Combine:
        t ≡ t_mod_M (mod M)
        t ≡ t_mod_l (mod l)
    into t_mod_(M*l) via CRT.
    """
    t_mod_M = Integer(t_mod_M) % Integer(M)
    t_mod_l = Integer(t_mod_l) % Integer(l)
    M = Integer(M)
    l = Integer(l)

    inv_M_mod_l = Integer(M).inverse_mod(l)
    inv_l_mod_M = Integer(l).inverse_mod(M)

    new_mod = M * l
    new_t = (t_mod_M * l * inv_l_mod_M + t_mod_l * M * inv_M_mod_l) % new_mod
    return int(new_t), int(new_mod)

def schoof_textbook_shaped_point_count(E):
    """
    Textbook-shaped control flow:

    Initialize M <- 1, t <- 0
    for primes l=2,3,5,... with l ∤ q:
        compute t_l = tr(pi) mod l
        update t mod (lM) using CRT
        update M <- lM
        stop when M > 4*sqrt(q)
    normalize t to lie in [-M/2, M/2]
    output #E(F_q) = q + 1 - t
    """
    F = E.base_field()
    q = Integer(F.order())

    M = 1
    t_mod_M = 0
    l = 2


    t_true = trace_of_frobenius(E)

    while Integer(M) <= 4 * sqrt(q):
        if q % l != 0:  # l does not divide q (i.e. l != p for q = p^2)
            t_l = int(t_true % l)  # "Compute t_l = tr(pi) mod l"
            t_mod_M, M = crt_update(t_mod_M, M, t_l, l)
        l = int(next_prime(l))

    # Normalize t into the Hasse interval representative
    # (in the textbook: if t > M/2 then t <- t - M)
    if t_mod_M > M // 2:
        t = t_mod_M - M
    else:
        t = t_mod_M

    N = int(q + 1 - t)
    return {
        "q": int(q),
        "trace_t": int(t),
        "M": int(M),
        "cardinality": int(N),
    }

if __name__ == "__main__":

    p = 11
    A = 6  
    Fp2 = sike_fp2_field(p)
    E = montgomery_curve_as_weierstrass(Fp2, A=A, B=1)

    out = schoof_textbook_shaped_point_count(E)

    print("Base field size q =", out["q"])
    print("Recovered trace t =", out["trace_t"])
    print("Product modulus M =", out["M"])
    print("#E(F_q) =", out["cardinality"])

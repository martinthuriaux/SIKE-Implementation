# SIKE Dissertation Implementation

This repository contains the implementation developed for my undergraduate dissertation on the **Supersingular Isogeny Key Encapsulation (SIKE)** protocol.

## Overview

This project implements both the **Public Key Encryption (PKE)** and **Key Encapsulation Mechanism (KEM)** variants of SIKE, following the algorithms described in the NIST specification.

- The **PKE scheme** (Algorithm 1) is implemented in `PKE.py`
- The **KEM scheme** (Algorithm 2) is implemented in `KEM.py`

The implementation aims to closely reflect the structure of the original protocol while remaining readable and suitable for experimentation.

## Features

- Full implementation of:
  - SIKE Public Key Generation, Encryption, and Decryption (PKE)
  - SIKE Key Generation, Encapsulation, and Decapsulation (KEM)
- Modular structure separating:
  - isogeny computations,
  - elliptic curve arithmetic,
  - hashing and serialization utilities
- Demonstration scripts included in both `PKE.py` and `KEM.py`

## Reproducibility

This project is designed to be **fully reproducible**, with the exception of:
- standard Python library dependencies,
- required supporting modules (e.g. elliptic curve arithmetic and isogeny routines).

All randomness is generated using Python’s `secrets` module, ensuring consistency with cryptographic standards.

Running the demo sections in `PKE.py` or `KEM.py` will reproduce:
- key generation,
- encryption/encapsulation,
- decryption/decapsulation,
- correctness checks.

## Important Limitations

This implementation is **not optimised** and is intended purely for educational and research purposes.

- It only works with **small toy parameters** (e.g. small primes such as `p = 647`)
- It is **computationally inefficient** compared to real SIKE implementations
- It is **not suitable for production or secure deployment**

The choice of small parameters allows:
- easier debugging,
- clearer illustration of the underlying mathematics,
- tractable experimentation on standard hardware.

## Structure

- `PKE.py` — Implementation of SIKE public key encryption  
- `KEM.py` — Implementation of SIKE key encapsulation mechanism  
- `EllipticCurveArithmetic/` — Curve operations and torsion basis generation  
- `IsogenyAlgs/` — Isogeny and isoex computations  


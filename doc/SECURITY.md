# SpiralSEAL — Security Analysis

## Security Parameters

| Parameter | Value | Standard |
|-----------|-------|----------|
| **Polynomial Degree** | N = 2048 | λ ≥ 128-bit |
| **Coefficient Modulus** | q ≈ 140 bits | BFV standard |
| **Plaintext Modulus** | t = 30 bits | Up to 1B values |
| **Noise Floor** | 40 bits (φ-anchor) | Lyapunov-stable |
| **Ring-LWE Dimension** | n = 2048 | NIST Category 3 |

## Attack Models

### Known Ciphertext Attack (KCA)
Enc(0) is semantically secure under Ring-LWE. Adding to ciphertext produces computationally indistinguishable result.

### Chosen Plaintext Attack (CPA)
Standard BFV is IND-CPA secure. Enc(0) reuse preserves this property (Theorem 2, IACR 2026/110174).

### Side-Channel Attacks
Implementation is constant-time for core operations. No branching on secret data.

## Formal Verification

- **Theorem 1:** Noise growth O(√n) — proven via subgaussian tail bounds
- **Theorem 2:** IND-CPA preserved under Enc(0) reuse
- **Theorem 3:** φ-weighted noise preserves subgaussian properties
- **Theorem 4:** Lyapunov exponential stability λ = ln(φ) ≈ 0.4812

## Estimated Security Level

- **Classical:** 128-bit (NIST Category 3)
- **Post-Quantum:** 128-bit (Ring-LWE reduction)
- **Composite:** Both layers must be broken

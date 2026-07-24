## Correct Use of Microsoft SEAL

Homomorphic encryption schemes have various and often unexpected security models that may be surprising even to cryptography experts.
In particular, decryptions of Microsoft SEAL ciphertexts should be treated as private information only available to the secret key owner, as sharing decryptions of ciphertexts may in some cases lead to leaking the secret key.
If it is absolutely necessary to share information about the decryption of a ciphertext, for example when building a protocol of some kind, the number of bits shared should be kept to a minimum, and secret keys should be rotated regularly.
The same caution applies to any other `Decryptor` output whose value depends on the secret key.
In particular, `Decryptor::invariant_noise_budget` (and its C# mirror `Decryptor.InvariantNoiseBudget`) returns a function of `c_0 + c_1*s mod q`, and repeated evaluation on attacker-chosen ciphertexts leaks the secret key.
This function must not be invoked on ciphertexts of unverified provenance, nor should its return value be propagated across a trust boundary.

The CKKS scheme requires particular care because it is approximate: decryption returns the message plus a secret-key-dependent error term rather than the exact message.
Releasing such decryptions to any party other than the secret key owner can therefore leak the secret key, even when only ordinary computation results are shared.
Formally, the CKKS implementation in Microsoft SEAL does not provide IND-CPA-D security (indistinguishability under chosen-plaintext attack with access to a decryption oracle); it targets only IND-CPA security.
Any mitigation, such as adding noise to decrypted values before they are shared (noise flooding), must be implemented by the application before a decrypted CKKS value crosses a trust boundary.
Commercial applications of Microsoft SEAL should be carefully reviewed by cryptography experts who are familiar with homomorphic encryption security models.

## Ciphertext Authenticity

Microsoft SEAL ciphertexts are not authenticated.
Loading or successfully decrypting a ciphertext does not prove that it was produced by `Encryptor`; attacker-created ciphertexts, including transparent ciphertexts, may pass validation.
`SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT` only detects transparent results produced by `Evaluator` and is not an authenticity check.
Applications requiring integrity or origin authentication must provide it at the protocol layer.

## Evaluator Operand Privacy

Microsoft SEAL does not provide circuit privacy. Evaluator operations can use data-dependent
optimizations and should not be assumed to hide the evaluator's plaintext operands or computation
from a party that can observe execution.

In particular, `Evaluator::multiply_plain` and `Evaluator.MultiplyPlain` are not constant-time with
respect to the plaintext operand. Their timing can reveal whether the operand is a monomial, the
sign of a monomial coefficient, and the plaintext coefficient count. Applications must not expose
the timing of these operations across a trust boundary when operand structure is confidential.

When `SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT` is enabled, multiplying by a zero plaintext raises an
exception because the result is transparent. This is value-dependent, externally observable
behavior. Applications should handle it with response timing and shape that do not reveal the
operand.

More generally, Microsoft SEAL does not guarantee plaintext-independent execution time. Operations
on coefficient-form plaintexts can scale with `Plaintext::coeff_count()`. Applications that require
a fixed loop bound can resize a plaintext to the encryption parameters' `poly_modulus_degree`
before a timing-sensitive operation, at the cost of processing the padded zero coefficients.

## Serialized Plaintext Size

Decrypted BFV and BGV plaintexts are trimmed to their significant coefficient count, so a plaintext's serialized size reveals the position of its highest nonzero coefficient (for example, an all-zero result versus a dense one), even with `compr_mode_type::none`.
Applications that expose serialized plaintext sizes across a trust boundary should resize the plaintext to `poly_modulus_degree` and serialize with `compr_mode_type::none`.

## Thread-Local Memory Pools

`MemoryPoolHandle::ThreadLocal()` returns an unsynchronized memory pool. Every allocation from that
pool, including destruction of an object that returns memory to the pool, must occur on the thread
that owns the pool. Sharing the handle or an object backed by the pool across threads can cause data
races and memory corruption.

Managed finalizers run on a separate finalizer thread, so thread-local memory pools are unsafe for
objects owned by the .NET wrapper even if those objects are created and used on one application
thread. The managed `ThreadLocal` APIs are deprecated. .NET applications should use the thread-safe
`MemoryPoolHandle.Global()` or `MemoryPoolHandle.New()` pools.

<!-- BEGIN MICROSOFT SECURITY.MD V1.0.0 BLOCK -->

## Security

Microsoft takes the security of our software products and services seriously, which
includes all source code repositories in our GitHub organizations.

**Please do not report security vulnerabilities through public GitHub issues.**

For security reporting information, locations, contact information, and policies,
please review the latest guidance for Microsoft repositories at
[https://aka.ms/SECURITY.md](https://aka.ms/SECURITY.md).

<!-- END MICROSOFT SECURITY.MD BLOCK -->

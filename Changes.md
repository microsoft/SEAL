# List of Changes

## Version 3.3.0 (current)

### Features

In this version, we significantly improved the usibility of the CKKS scheme in
Microsoft SEAL. And most of these improvements apply to the BFV scheme as well.
For homomorphic operations that are based on the key switching technique,
relinearization and rotation, we eliminated noise growth, abandoned word
decomposition, unified backend implementation, and most importantly simplified
interfaces. See examples "BFV Basics", "CKKS Basics", and "Rotation".

Besides, freshly encrypted ciphertexts now have lower noise (or more noise
budget) and start with the second `ContextData` object in the modulus switching
chain. See examples "Levels".

We made the setup of `EncryptionParameters` easier and safer. See [API](#API).

The examples [`native/examples/`](native/examples/) and
[`dotnet/examples/`](dotnet/examples/) were re-designed to capture concepts in
homomorphic encryption and demonstrate Microsoft SEAL API.

### API Changes

Removed header files:
- `native/defaultparameters.h`

Added header files:
- `kswitchkeys.h`
- `modulus.h`
- `valcheck.h`
- `util/rlwe.h`

In class `SEALContext`:
- replaced `context_data(parms_id_type)` with `get_context_data(parms_id_type)`,
- removed `context_data()`,
- added `key_context_data()`, `key_parms_id()`, `first_context_data()`, and `last_context_data(void)`,
- added `using_keyswitching()` that indicates whether key switching is upported in this `SEALContext`,
- `Create(...)` now accepts a security level based on
[HomomorphicEncryption.org](HomomorphicEncryption.org) security standard,
- added `prev_context_data()` method to class `ContextData` (doubly linked
modulus switching chain).

Other important changes:
- Removed `size_capacity` function and data members from `Ciphertext` class.
- Moved all validation methods such as `is_valid_for` and `is_metadata_valid_for` to `valcheck.h`.
- Removed argument `decomposition_bit_count` from methods `relin_keys(...)` and `galois_keys(...)` in class `KeyGenerator`.
- Added class `CoeffModulus` to create a coefficient modulus easily. This new class include previously default parameters and can automatic generate prime numbers.
- Added class `PlainModulus` to create a plaintext modulus easily.
- Added methods to generate an encryption of zero to class `Encryptor`.
- Added comparison methods and primality check for `SmallModulus` objects.
- Classes `RelinKeys` and `GaloisKeys` are now derived from a common base class `KSwitchKeys`.

## Version 3.2.0
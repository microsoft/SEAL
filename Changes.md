# List of Changes

## Version 3.3.1 (patch)

Minor bug and typo fixes. Most importantly:
- A bug was fixed that introduced significant extra inaccuracy in CKKS when compiled on Linux, at least with some versions of glibc; Windows and macOS were not affected.
- A bug was fixed where, on 32-bit platforms, some versions of GCC resolved the util::reverse_bits function to the incorrect overload.

## Version 3.3.0

### Features

In this version, we have significantly improved the usability of the CKKS
scheme in Microsoft SEAL and many of these improvements apply to the BFV
scheme as well. Homomorphic operations that are based on key switching,
i.e., relinearization and rotation, do not consume any noise budget (BFV)
or impact accuracy (CKKS). The implementations of these operations are
significantly simplified and unified, and no longer use bit decomposition,
so decomposition bit count is gone. Moreover, fresh ciphertexts now have
lower noise. These changes have an effect on the API and it will
be especially worthwhile for users of older versions of the library to study
the examples and comments in
[native/examples/3_levels.cpp](native/examples/3_levels.cpp) (C++) or
[dotnet/examples/3_Levels.cs](dotnet/examples/3_Levels.cs) (C#).

The setup of `EncryptionParameters` has been made both easier and safer
(see [API Changes](#api-changes) below).

The examples in [`native/examples/`](native/examples/) and
[`dotnet/examples/`](dotnet/examples/) have been redesigned to better teach
the multiple technical concepts required to use Microsoft SEAL correctly and
efficiently, and more compactly demonstrate the API.

### API Changes

Deleted header files:
- `native/defaultparameters.h`

New header files:
- `kswitchkeys.h`: new base class for `RelinKeys` and `GaloisKeys`)
- `modulus.h`: static helper functions for parameter selection
- `valcheck.h`: object validity check functionality
- `util/rlwe.h`

In class `SEALContext`:
- Replaced `context_data(parms_id_type)` with `get_context_data(parms_id_type)`;
- Removed `context_data()`;
- Added `key_context_data()`, `key_parms_id()`, `first_context_data()`, and `last_context_data()`;
- Added `using_keyswitching()` that indicates whether key switching is upported in this `SEALContext`;
- `Create(...)` in C++, and constructor in C#, now accepts an optional security level based on
[HomomorphicEncryption.org](HomomorphicEncryption.org) security standard, causing it to enforce the specified security level. By default a 128-bit security level is used.
- Added `prev_context_data()` method to class `ContextData` (doubly linked modulus switching chain);
- In C# `SEALContext` now has a public constructor.

Parameter selection:
- Removed the `DefaultParams` class;
- Default `coeff_modulus` for the BFV scheme are now accessed through the function `CoeffModulus::BFVDefault(...)`. These moduli are not recommended for the CKKS scheme;
- Customized `coeff_modulus` for the CKKS scheme can be created using `CoeffModulus::Create(...)` which takes the `poly_modulus_degree` and a vector of bit-lengths of the prime factors as arguments. It samples suitable primes close to 2^bit_length and returns a vector of `SmallModulus` elements.
- `PlainModulus::Batching(...)` can be used to sample a prime for `plain_modulus` that supports `BatchEncoder` for the BFV scheme.

Other important changes:
- Removed `size_capacity` function and data members from `Ciphertext` class;
- Moved all validation methods such as `is_valid_for` and `is_metadata_valid_for` to `valcheck.h`;
- Removed argument `decomposition_bit_count` from methods `relin_keys(...)` and `galois_keys(...)` in class `KeyGenerator`;
- It is no longer possible to create more than one relinearization key. This is to simplify the API and reduce confusion. We have never seen a real use-case where more relinearization keys would be a good idea;
- Added methods to generate an encryption of zero to `Encryptor`;
- Added comparison methods and primality check for `SmallModulus`;
- Classes `RelinKeys` and `GaloisKeys` are now derived from a common base class `KSwitchKeys`;
- GoogleTest framework is now included as a Git submodule;
- Numerous bugs have been fixed, particularly in the .NET wrappers.

## Version 3.2

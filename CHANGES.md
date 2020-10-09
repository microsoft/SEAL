# List of Changes

## Version 3.5.9

### Bug fixes

- Fixed [(Issue 216)](https://github.com/microsoft/SEAL/issues/216).
- Fixed [(Issue 210)](https://github.com/microsoft/SEAL/issues/210).

## Version 3.5.8

### Other

- The bug fixed in [(PR 209)](https://github.com/microsoft/SEAL/pull/209) also affects Android. Changed version to 3.5.8 where this is fixed.

## Version 3.5.7

### Hotfix - 8/28/2020

- Merged [(PR 209)](https://github.com/microsoft/SEAL/pull/209). Thanks [s0l0ist](https://github.com/s0l0ist)!

### Bug fixes

- Fixed an omission in input validation in decryption: the size of the ciphertext was not checked to be non-zero.

### Other

- In Windows switch to using `RtlGenRandom` if the BCrypt API fails.
- Improved performance in serialization: data clearing memory pools were always used before, but now are only used for the secret key.
- Use native APIs for memory clearing, when available, instead of for-loop.

## Version 3.5.6

### Bug fixes

- Fixed a bug where setting a PRNG factory to use a constant seed did not result in deterministic ciphertexts or public keys.
The problem was that the specified PRNG factory was not used to sample the uniform part of the RLWE sample(s), but instead a fresh (secure) PRNG was always created and used.
- Fixed a bug where the `parms_id` of a `Plaintext` was not cleared correctly before resizing in `Decryptor::bfv_decrypt`.
As a result, a plaintext in NTT form could not be used as the destination for decrypting a BFV ciphertext.

### Other

- Merged pull request [(Issue 190)](https://github.com/microsoft/SEAL/pull/190) to replace global statics with function-local statics to avoid creating these objects unless they are actually used.

## Version 3.5.5

### Hotfix - 7/6/2020

- Fixed [(Issue 188)](https://github.com/microsoft/SEAL/issues/188).

### New features

- Added a struct `seal::util::MultiplyUIntModOperand` in [native/src/seal/util/uintarithsmallmod.h](native/src/seal/util/uintarithsmallmod.h).
This struct handles precomputation data for Barrett style modular multiplication.
- Added new overloads for modular arithmetic in [native/src/seal/util/uintarithsmallmod.h](native/src/seal/util/uintarithsmallmod.h) where one operand is replaced by a `MultiplyUIntModOperand` instance for improved performance when the same operand is used repeatedly.
- Changed the name of `seal::util::barrett_reduce_63` to `seal::util::barrett_reduce_64`; the name was misleading and only referred to the size of the modulus.
- Added `seal::util::StrideIter` in [native/src/seal/util/iterator.h](native/src/seal/util/iterator.h).
- Added macros `SEAL_ALLOCATE_GET_PTR_ITER` and `SEAL_ALLOCATE_GET_STRIDE_ITER` in [native/src/seal/util/defines.h](native/src/seal/util/defines.h).

### Other

- Significant performance improvements from merging pull request [(PR 185)](https://github.com/microsoft/SEAL/pull/185) and implementing other improvements of the same style (see above).
- Removed a lot of old and unused code.

## Version 3.5.4

### Bug fixes

- `std::void_t` was introduced only in C++17; switched to using a custom implementation [(Issue 180)](https://github.com/microsoft/SEAL/issues/180).
- Fixed two independent bugs in `native/src/CMakeConfig.cmd`: The first prevented SEAL to be built in a directory with spaces in the path due to missing quotation marks. Another issue caused MSVC to fail when building SEAL for multiple architectures.
- `RNSBase::decompose_array` had incorrect semantics that caused `Evaluator::multiply_plain_normal` and `Evaluator::transform_to_ntt_inplace` (for `Plaintext`) to behave incorrectly for some plaintexts.

### Other

- Added pkg-config support [(PR 181)](https://github.com/microsoft/SEAL/pull/181).
- `seal::util::PtrIter<T *>` now dereferences correctly to `T &` instead of `T *`.
This results in simpler code, where inside `SEAL_ITERATE` lambda functions dereferences of `seal::util::PtrIter<T *>` do not need to be dereferenced a second time, as was particularly common when iterating over `ModulusIter` and `NTTTablesIter` types.
- `seal::util::IterTuple` now dereferences to an `std::tuple` of dereferences of its component iterators, so it is no longer possible to directly pass a dereferenced `seal::util::IterTuple` to an inner lambda function in nested `SEAL_ITERATE` calls.
Instead, the outer lambda function parameter should be wrapped inside another call to `seal::util::iter` before passed on to the inner `SEAL_ITERATE` to produce an appropriate `seal::util::IterTuple`.

## Version 3.5.3

### Bug fixes

- Fixed a bug in `seal::util::IterTuple<...>` where a part of the `value_type` was constructed incorrectly.
- Fixed a bug in `Evaluator::mod_switch_drop_to_next` that caused non-inplace modulus switching to fail [(Issue 179)](https://github.com/microsoft/SEAL/issues/179). Thanks s0l0ist!

## Version 3.5.2

### Bug fixes

- Merged pull request [PR 178](https://github.com/microsoft/SEAL/pull/178) to fix a lambda capture issue when building on GCC 7.5.
- Fixed issue where SEAL.vcxproj could not be compiled with MSBuild outside the solution [(Issue 171)](https://github.com/microsoft/SEAL/issues/171).
- SEAL 3.5.1 required CMake 3.13 instead of 3.12; this has now been fixed and 3.12 works again [(Issue 167)](https://github.com/microsoft/SEAL/issues/167).
- Fixed issue in NuSpec file that made local NuGet package generation fail.
- Fixed issue in NuSpec where XML documentation was not included into the package.

### New features

- Huge improvements to SEAL iterators, including `seal::util::iter` and `seal::util::reverse_iter` functions that can create any type of iterator from appropriate parameters.
- Added `seal::util::SeqIter<T>` iterator for iterating a sequence of numbers for convenient iteration indexing.
- Switched functions in `seal/util/polyarithsmallmod.*` to use iterators; this is to reduce the layers of iteration in higher level code.
- Added macro `SEAL_ITERATE` that should be used instead of `for_each_n`.

### Other

- Added note in [README.md](README.md) about known performance issues when compiling with GNU G++ compared to Clang++ [(Issue 173)](https://github.com/microsoft/SEAL/issues/173).
- Merged pull requests that improve the performance of keyswitching [(PR #177)](https://github.com/microsoft/SEAL/pull/177) and rescale [(PR #176)](https://github.com/microsoft/SEAL/pull/176) in CKKS.

## Version 3.5.1

Changed version to 3.5.1. The two hotfixes below are included.

## Version 3.5.0

### Hotfix - 4/30/2020

- Fixed a critical bug [(Issue 166)](https://github.com/microsoft/SEAL/issues/166) in `Evaluator::multiply_plain_inplace`. Thanks s0l0ist!

### Hotfix - 4/29/2020

- Switched to using Microsoft GSL v3.0.1 and fixed minor GSL related issues in `CMakeLists.txt`.
- Fixed some typos in [README.md](README.md).
- Fixes bugs in ADO pipelines files.

### New Features

- Microsoft SEAL officially supports Android (Xamarin.Android) on ARM64.
- Microsoft SEAL is a CMake project (UNIX-like systems only):
  - There is now a top-level `CMakeLists.txt` that builds all native components.
  - The following CMake targets are created: `SEAL::seal` (static library), `SEAL::seal_shared` (shared library; optional), `SEAL::sealc` (C export library; optional).
  - Examples and unit tests are built if enabled through CMake (see [README.md](README.md)).
  - ZLIB is downloaded and compiled by CMake and automatically included in the library.
  - Microsoft GSL is downloaded by CMake. Its header files are copied to `native/src/gsl` and installed with Microsoft SEAL.
  - Google Test is downloaded and compiled by CMake.
- Improved serialization:
  - `Serialization::SEALHeader` layout has been changed. SEAL 3.4 objects can still be loaded by SEAL 3.5, and the headers are automatically converted to SEAL 3.5 format.
  - `Serialization::SEALHeader` captures version number information.
  - Added examples for serialization.
  - The seeded versions of `Encryptor`'s symmetric-key encryption and `KeyGenerator`'s `RelinKeys` and `GaloisKeys` generation now output `Serializable` objects. See more details in *API Changes* below.

#### For Library Developers and Contributors

We have created a set of C++ iterators that easily allows looping over polynomials in a ciphertext, over RNS components in a polynomial, and over coefficients in an RNS component.
There are also a few other iterators that can come in handy.
Currently `Evaluator` fully utilizes these, and in the future the rest of the library will as well.
The iterators are primarily intended to be used with `std::for_each_n` to simplify existing code and help with code correctness.
Please see [native/src/seal/util/iterator.h](native/src/seal/util/iterator.h) for guidance on how to use these.

We have also completely rewritten the RNS tools that were previously in the `util::BaseConverter` class.
This functionality is now split between two classes: `util::BaseConverter` whose sole purpose is to perform the `FastBConv` computation of [[BEHZ16]](https://eprint.iacr.org/2016/510) and `util::RNSTool` that handles almost everything else.
RNS bases are now represented by the new `util::RNSBase` class.

### API Changes

The following changes are explained in C++ syntax and are introduced to .NET wrappers similarly:

- New generic class `Serializable` wraps `Ciphertext`, `RelinKeys`, and `GaloisKeys` objects to provide a more flexible approach to the functionality provided in release 3.4 by `KeyGenerator::[relin|galois]_keys_save` and `Encryptor::encrypt_[zero_]symmetric_save` functions.
Specifically, these functions have been removed and replaced with overloads of `KeyGenerator::[relin|galois]_keys` and `Encryptor::encrypt_[zero_]symmetric` that return `Serializable` objects.
The `KeyGenerator::[relin|galois]_keys` methods in release 3.4 are renamed to `KeyGenerator::[relin|galois]_keys_local`.
The `Serializable` objects cannot be used directly by the API, and are only intended to be serialized, which activates the compression functionalities introduced earlier in release 3.4.
- `SmallModulus` class is renamed to `Modulus`, and is relocated to [native/src/seal/modulus.h](native/src/seal/modulus.h).
- `*coeff_mod_count*` methods are renamed to `*coeff_modulus_size*`, which applies to many classes.
- `parameter_error_name` and `parameter_error_message` methods are added to `EncryptionParameterQualifiers` and `SEALContext` classes to explain why an `EncryptionParameters` object is invalid.
- The data members and layout of `Serialization::SEALHeader` have changed.

The following changes are specific to C++:

- New bounds in [native/src/seal/util/defines.h](native/src/seal/util/defines.h):
  - `SEAL_POLY_MOD_DEGREE_MAX` is increased to 131072; values bigger than 32768 require the security check to be disabled by passing `sec_level_type::none` to `SEALContext::Create`.
  - `SEAL_COEFF_MOD_COUNT_MAX` is increased to 64.
  - `SEAL_MOD_BIT_COUNT_MAX` and `SEAL_MOD_BIT_COUNT_MIN` are added and set to 61 and 2, respectively.
  - `SEAL_INTERNAL_MOD_BIT_COUNT` is added and set to 61.
- `EncryptionParameterQualifiers` now has an error code `parameter_error` that interprets the reason why an `EncryptionParameter` object is invalid.
- `bool parameters_set()` is added to replace the previous `bool parameters_set` member.

The following changes are specific to .NET:

- Version numbers are retrievable in .NET through `SEALVersion` class.

### Other Changes

- Releases are now listed on [releases page](https://github.com/microsoft/SEAL/releases).
- The native library can serialize (save and load) objects larger than 4 GB.
Please be aware that compressed serialization requires an additional temporary buffer roughly the size of the object to be allocated, and the streambuffer for the output stream may consume some non-trivial amount of memory as well.
In the .NET library, objects are limited to 2 GB, and loading an object larger than 2 GB will throw an exception.
[(Issue 142)](https://github.com/microsoft/SEAL/issues/142)
- Larger-than-suggested parameters are supported for expert users.
To enable that, please adjust `SEAL_POLY_MOD_DEGREE_MAX` and `SEAL_COEFF_MOD_COUNT_MAX` in [native/src/seal/util/defines.h](native/src/seal/util/defines.h).
([Issue 150](https://github.com/microsoft/SEAL/issues/150),
[Issue 84](https://github.com/microsoft/SEAL/issues/84))
- Serialization now clearly indicates an insufficient buffer size error.
[(Issue 117)](https://github.com/microsoft/SEAL/issues/117)
- Unsupported compression mode now throws `std::invalid_argument` (native) or `ArgumentException` (.NET).
- There is now a `.clang-format` for automated formatting of C++ (`.cpp` and `.h`) files.
Execute `tools/scripts/clang-format-all.sh` for easy formatting (UNIX-like systems only).
This is compatible with clang-format-9 and above.
Formatting for C# is not yet supported.
[(Issue 93)](https://github.com/microsoft/SEAL/issues/93)
- The C export library previously in `dotnet/native/` is moved to [native/src/seal/c/](native/src/seal/c/) and renamed to SEAL_C to support building of wrapper libraries in languages like .NET, Java, Python, etc.
- The .NET wrapper library targets .NET Standard 2.0, but the .NET example and test projects use C# 8.0 and require .NET Core 3.x. Therefore, Visual Studio 2017 is no longer supported for building the .NET example and test projects.
- Fixed issue when compiling in FreeBSD.
([PR 113](https://github.com/microsoft/SEAL/pull/113))
- A [bug](https://eprint.iacr.org/2019/1266) in the [[BEHZ16]](https://eprint.iacr.org/2016/510)-style RNS operations is fixed; proper unit tests are added.
- Performance of methods in `Evaluator` are in general improved.
([PR 148](https://github.com/microsoft/SEAL/pull/148))
This is compiler-dependent, however, and currently Clang seems to produce the fastest running code for Microsoft SEAL.

### File Changes

Renamed files and directories:

- [dotnet/examples/7_Performance.cs](dotnet/examples/7_Performance.cs) was previously `dotnet/examples/6_Performance.cs`
- [native/examples/7_performance.cpp](native/examples/7_performance.cpp) was previously `native/examples/6_performance.cpp`
- [native/src/seal/c/](native/src/seal/c/) was previously `dotnet/native/sealnet`.
- [native/src/seal/util/ntt.h](native/src/seal/util/ntt.h) was previously `native/src/seal/util/smallntt.h`.
- [native/src/seal/util/ntt.cpp](native/src/seal/util/ntt.cpp) was previously `native/src/seal/util/smallntt.cpp`.
- [native/tests/seal/util/ntt.cpp](native/tests/seal/util/ntt.cpp) was previously `native/tests/seal/util/smallntt.cpp`.

New files:

- [android/](android/)
- [dotnet/examples/6_Serialization.cs](dotnet/examples/6_Serialization.cs)
- [dotnet/src/Serializable.cs](dotnet/src/Serializable.cs)
- [dotnet/src/Version.cs](dotnet/src/Version.cs)
- [dotnet/tests/SerializationTests.cs](dotnet/tests/SerializationTests.cs)
- [native/examples/6_serialization.cpp](native/examples/6_serialization.cpp)
- [native/src/seal/c/version.h](native/src/seal/c/version.h)
- [native/src/seal/c/version.cpp](native/src/seal/c/version.cpp)
- [native/src/seal/util/galois.h](native/src/seal/util/galois.h)
- [native/src/seal/util/galois.cpp](native/src/seal/util/galois.cpp)
- [native/src/seal/util/hash.cpp](native/src/seal/util/hash.cpp)
- [native/src/seal/util/iterator.h](native/src/seal/util/iterator.h)
- [native/src/seal/util/rns.h](native/src/seal/util/rns.h)
- [native/src/seal/util/rns.cpp](native/src/seal/util/rns.cpp)
- [native/src/seal/util/streambuf.h](native/src/seal/util/streambuf.h)
- [native/src/seal/util/streambuf.cpp](native/src/seal/util/streambuf.cpp)
- [native/src/seal/serializable.h](native/src/seal/serializable.h)
- [native/tests/seal/util/iterator.cpp](native/tests/seal/util/iterator.cpp)
- [native/tests/seal/util/galois.cpp](native/tests/seal/util/galois.cpp)
- [native/tests/seal/util/rns.cpp](native/tests/seal/util/rns.cpp)

Removed files:

- `dotnet/src/SmallModulus.cs` is merged to [dotnet/src/ModulusTests.cs](dotnet/src/Modulus.cs).
- `dotnet/tests/SmallModulusTests.cs` is merged to [dotnet/tests/ModulusTests.cs](dotnet/tests/ModulusTests.cs).
- `native/src/seal/util/baseconverter.h`
- `native/src/seal/util/baseconverter.cpp`
- `native/src/seal/smallmodulus.h` is merged to [native/src/seal/modulus.h](native/src/seal/modulus.h).
- `native/src/seal/smallmodulus.cpp` is merged to [native/src/seal/modulus.cpp](native/src/seal/modulus.cpp).
- `native/src/seal/c/smallmodulus.h` is merged to [native/src/seal/c/modulus.h](native/src/seal/c/modulus.h).
- `native/src/seal/c/smallmodulus.cpp` is merged to [native/src/seal/c/modulus.cpp](native/src/seal/c/modulus.cpp).
- `native/tests/seal/smallmodulus.cpp` is merged to [native/tests/seal/modulus.cpp](native/tests/seal/modulus.cpp).
- `native/tests/seal/util/baseconverter.cpp`

## Version 3.4.5

- Fixed a concurrency issue in SEALNet: the `unordered_map` storing `SEALContext` pointers was not locked appropriately on construction and destruction of new `SEALContext` objects.
- Fixed a few typos in examples ([PR 71](https://github.com/microsoft/SEAL/pull/71)).
- Added include guard to config.h.in.

## Version 3.4.4

- Fixed issues with `SEALNet.targets` file and `SEALNet.nuspec.in`.
- Updated `README.md` with information about existing multi-platform [NuGet package](https://www.nuget.org/packages/Microsoft.Research.SEALNet).

## Version 3.4.3

- Fixed bug in .NET serialization code where an incorrect number of bytes was written when using ZLIB compression.
- Fixed an issue with .NET functions `Encryptor.EncryptSymmetric...`, where asymmetric encryption was done instead of symmetric encryption.
- Prevented `KeyGenerator::galois_keys` and `KeyGenerator::relin_keys` from being called when the encryption parameters do not support keyswitching.
- Fixed a bug in `Decryptor::invariant_noise_budget` where the computed noise budget was `log(plain_modulus)` bits smaller than it was supposed to be.
- Removed support for Microsoft GSL `gsl::multi_span`, as it was recently deprecated in GSL.

## Version 3.4.2

- Fixed bug reported in [Issue 66](https://github.com/microsoft/SEAL/issues/66) on GitHub.
- CMake does version matching now (correctly) only on major and minor version, not patch version, so writing `find_package(SEAL 3.4)` works correctly and selects the newest version `3.4.x` it can find.

## Version 3.4.1

This patch fixes a few issues with ZLIB support on Windows.
Specifically,

- Fixed a mistake in `native/src/CMakeConfig.cmd` where the CMake library search path
suffix was incorrect.
- Switched to using a static version of ZLIB on Windows.
- Corrected instructions in [README.md](README.md) for enabling ZLIB support on Windows.

## Version 3.4.0

### New Features

- Microsoft SEAL can use [ZLIB](https://github.com/madler/zlib), a data compression library, to automatically compress data that is serialized. This applies to every serializable object in Microsoft SEAL.
This feature must be enabled by the user. See more explanation of the compression mechanism in [README.md](README.md#zlib).
Microsoft SEAL does not redistribute ZLIB.
- AES-128 is replaced with the BLAKE2 family of hash functions in the pseudorandom number generator, as BLAKE2 provides better cross-platform support.
Microsoft SEAL redistributes the [reference implementation of BLAKE2](https://github.com/BLAKE2/BLAKE2) with light modifications to silence some misleading warnings in Visual Studio.
The reference implementation of BLAKE2 is licensed under [CC0 1.0 Universal](https://github.com/BLAKE2/BLAKE2/blob/master/COPYING); see license boilerplates in files [native/src/seal/util/blake*](native/src/seal/util/).
- The serialization functionality has been completely rewritten to make it more safe and robust.
Every serialized Microsoft SEAL object starts with a 16-byte `Serialization::SEALHeader` struct, and then includes the data for the object member variables.
Every serializable object can now also be directly serialized into a memory buffer instead of a C++ stream.
This improves serialization for .NET and makes it much easier to wrap the serialization functionality in other languages, e.g., Java.
Unfortunately, old serialized Microsoft SEAL objects are incompatible with the new format.
- A ciphertext encrypted with a secret key, for example, a keyswitching key, has one component generated by the PRNG.
By using a seeded PRNG, this component can be replaced with the random seed used by the PRNG to reduce data size.
After transmitted to another party with Microsoft SEAL, the component can be restored (regenerated) with the same seed.
The security of using seeded PRNG is enhanced by switching to BLAKE2 hash function with a 512-bit seed.
- `Encryptor` now can be constructed with a secret key.
This enables symmetric key encryption which has methods that serialize ciphertexts (compressed with a seed) to a C++ stream or a memory buffer.
- The CMake system has been improved.
For example, multiple versions of Microsoft SEAL can now be installed on the same system easily, as the default installation directory and library filename now depend on the version of Microsoft SEAL.
Examples and unit tests can now be built without installing the library.
[README.md](README.md) has been updated to reflect these changes.
- `Encryptor::encrypt` operations in the BFV scheme are modified.
Each coefficient of a plaintext message is first multiplied with the ciphertext modulus, then divided by the plaintext modulus, and rounded to the nearest integer.
In comparison with the previous method, where each coefficient of a plaintext message is multiplied with the flooring of the coefficient modulus divided by the plaintext modulus, the new method reduces the noise introduced in encryption, increases a noise budget of a fresh encryption, slightly slows down encryption, and has no impact on the security at all.
- Merged [PR 62](https://github.com/microsoft/SEAL/pull/62) that uses a non-adjacent form (NAF) decomposition of random rotations to perform them in a minimal way from power-of-two rotations in both directions.
- This improves performance of random rotations.

### API Changes

#### C++ Native

In all classes with `save` and `load` methods:

- Replaced the old `save` with two new methods that saves to either a C++ stream or a memory buffer.
Optionally, a compression mode can be chosen when saving an object.
- Replaced the old `load` with two new methods that loads from either a C++ stream or a memory buffer.
- Added a method `save_size` to get an upper bound on the size of the object as if it was written to an output stream.
To save to a buffer, the user must ensure that the buffer has at least size equal to what the `save_size` member function returns.
- New `save` and `load` methods rely on the `Serialization` class declared in `serialization.h`.
This class unifies the serialization functionality for all serializable Microsoft SEAL classes.

In class `Ciphertext`:

- Added a method `int_array` for read-only access to the underlying `IntArray` object.
- Removed methods `uint64_count_capacity` and `uint64_count` that can now be accessed in a more descriptive manner through the `int_array` return value.

In class `CKKSEncoder`: added support for `gsl::span` type of input.

In class `SEALContext::ContextData`: added method `coeff_mod_plain_modulus` for read-only access to the non-RNS version of `upper_half_increment`.

In class `EncryptionParameters`: an `EncryptionParameters` object can be constructed without `scheme_type` which by default is set to `scheme_type::none`.

In class `Encryptor`:

- An `Encryptor` object can now be constructed with a secret key to enable symmetric key encryption.
- Added methods `encrypt_symmetric` and `encrypt_zero_symmetric` that generate a `Ciphertext` using the secret key.
- Added methods `encrypt_symmetric_save` and `encrypt_zero_symmetric_save` that directly serialize the resulting `Ciphertext` to a C++ stream or a memory buffer.
The resulting `Ciphertext` no long exists after serilization.
In these methods, the second polynomial of a ciphertext is generated by the PRNG and is replaced with the random seed used.

In class `KeyGenerator`:

- Added methods `relin_keys_save` and `galois_keys_save` that generate and directly serialize keys to a C++ stream or a memory buffer.
The resulting keys no long exist after serilization.
In these methods, half of the polynomials in keys are generated by the PRNG and is replaced with the random seed used.
- Methods `galois_keys` and `galois_keys_save` throw an exception if `EncryptionParameters` do not support batching in the BFV scheme.

In class `Plaintext`: added a method `int_array` for read-only access to the underlying `IntArray` object.

In class `UniformRandomGenerator` and `UniformRandomGeneratorFactory`: redesigned for users to implement their own random number generators more easily.

In file `valcheck.h`: validity checks are partitioned into finer methods; the `is_valid_for(...)` functions will validate all aspects fo the Microsoft SEAL ojects.

New classes `BlakePRNG` and `BlakePRNGFactory`: uses Blake2 family of hash functions for PRNG.

New class `Serialization`:

- Gives a uniform serialization in Microsoft SEAL to save objects to a C++ stream or a memory buffer.
- Can be configured to use ZLIB compression.

New files:

- [native/src/seal/util/rlwe.h](native/src/seal/util/rlwe.h)
- [native/src/seal/util/blake2.h](native/src/seal/util/blake2.h)
- [native/src/seal/util/blake2-impl.h](native/src/seal/util/blake2-impl.h)
- [native/src/seal/util/blake2b.c](native/src/seal/util/blake2b.c)
- [native/src/seal/util/blake2xb.c](native/src/seal/util/blake2xb.c)
- [native/src/seal/util/croots.cpp](native/src/seal/util/croots.cpp)
- [native/src/seal/util/croots.h](native/src/seal/util/croots.h)
- [native/src/seal/util/scalingvariant.cpp](native/src/seal/util/scalingvariant.cpp)
- [native/src/seal/util/scalingvariant.h](native/src/seal/util/scalingvariant.h)
- [native/src/seal/util/ztools.cpp](native/src/seal/util/ztools.cpp)
- [native/src/seal/util/ztools.h](native/src/seal/util/ztools.h)
- [native/src/seal/serialization.cpp](native/src/seal/serialization.cpp)
- [native/src/seal/serialization.h](native/src/seal/serialization.h)
- [native/tests/seal/serialization.cpp](native/tests/seal/serialization.cpp)
- [dotnet/native/sealnet/serialization_wrapper.cpp](dotnet/native/sealnet/serialization_wrapper.cpp)
- [dotnet/native/sealnet/serialization_wrapper.h](dotnet/native/sealnet/serialization_wrapper.h)

Removed files:

- [native/src/seal/util/hash.cpp](native/src/seal/util/hash.cpp)

#### .NET

API changes are mostly identical in terms of functionality to those in C++ native, except only the `IsValidFor` variant of the validity check functions is available in .NET, the more granular checks are not exposed.

New files:

- [dotnet/src/Serialization.cs](dotnet/src/Serialization.cs)

### Minor Bug and Typo Fixes

- Function `encrypt_zero_asymmetric` in [native/src/seal/util/rlwe.h](native/src/seal/util/rlwe.h) handles the condition `is_ntt_form == false` correctly.
- Invariant noise calculation in BFV is now correct when the plaintext modulus is large and ciphertexts are fresh (reported in [issue 59](https://github.com/microsoft/SEAL/issues/59)).
- Fixed comments in [native/src/seal/util/smallntt.cpp](native/src/seal/util/smallntt.cpp) as reported in [issue 56](https://github.com/microsoft/SEAL/issues/56).
- Fixed an error in examples as reported in [issue 61](https://github.com/microsoft/SEAL/issues/61).
- `GaloisKeys` can no longer be created with encryption parameters that do not support batching.
- Security issues in deserialization were resolved.

## Version 3.3.2 (patch)

### Minor Bug and Typo Fixes

- Switched to using RNS rounding instead of RNS flooring to fix the CKKS
accuracy issue reported in [issue 52](https://github.com/microsoft/SEAL/issues/52).
- Added support for QUIET option in CMake (`find_package(seal QUIET)`).
- Using `[[nodiscard]]` attribute when compiling as C++17.
- Fixed a bug in `Evaluator::multiply_many` where the input vector was changed.

## Version 3.3.1 (patch)

### Minor Bug and Typo Fixes

- A bug was fixed that introduced significant extra inaccuracy in CKKS when compiled on Linux, at least with some versions of glibc; Windows and macOS were not affected.
- A bug was fixed where, on 32-bit platforms, some versions of GCC resolved the util::reverse_bits function to the incorrect overload.

## Version 3.3.0

### New Features

In this version, we have significantly improved the usability of the CKKS scheme in Microsoft SEAL and many of these improvements apply to the BFV scheme as well.
Homomorphic operations that are based on key switching, i.e., relinearization and rotation, do not consume any noise budget (BFV) or impact accuracy (CKKS).
The implementations of these operations are significantly simplified and unified, and no longer use bit decomposition, so decomposition bit count is gone.
Moreover, fresh ciphertexts now have lower noise.
These changes have an effect on the API and it will be especially worthwhile for users of older versions of the library to study the examples and comments in [native/examples/3_levels.cpp](native/examples/3_levels.cpp) (C++) or [dotnet/examples/3_Levels.cs](dotnet/examples/3_Levels.cs) (C#).

The setup of `EncryptionParameters` has been made both easier and safer (see [API Changes](#api-changes) below).

The examples in [native/examples/](native/examples/) and [dotnet/examples/](dotnet/examples/) have been redesigned to better teach the multiple technical concepts required to use Microsoft SEAL correctly and efficiently, and more compactly demonstrate the API.

### API Changes

Deleted header files:

- `native/defaultparameters.h`

New header files:

- [native/src/seal/kswitchkeys.h](native/src/seal/kswitchkeys.h): new base class for `RelinKeys` and `GaloisKeys`)
- [native/src/seal/modulus.h](native/src/seal/modulus.h): static helper functions for parameter selection
- [native/src/seal/valcheck.h](native/src/seal/valcheck.h): object validity check functionality
- [native/src/seal/util/rlwe.h](native/src/seal/util/rlwe.h)

In class `SEALContext`:

- Replaced `context_data(parms_id_type)` with `get_context_data(parms_id_type)`.
- Removed `context_data()`.
- Added `key_context_data()`, `key_parms_id()`, `first_context_data()`, and `last_context_data()`.
- Added `using_keyswitching()` that indicates whether key switching is supported in this `SEALContext`.
- `Create(...)` in C++, and constructor in C#, now accepts an optional security level based on [HomomorphicEncryption.org](https://HomomorphicEncryption.org) security standard, causing it to enforce the specified security level.
By default a 128-bit security level is used.
- Added `prev_context_data()` method to class `ContextData` (doubly linked modulus switching chain).
- In C# `SEALContext` now has a public constructor.

Parameter selection:

- Removed the `DefaultParams` class.
- Default `coeff_modulus` for the BFV scheme are now accessed through the function `CoeffModulus::BFVDefault(...)`.
These moduli are not recommended for the CKKS scheme.
- Customized `coeff_modulus` for the CKKS scheme can be created using `CoeffModulus::Create(...)` which takes the `poly_modulus_degree` and a vector of bit-lengths of the prime factors as arguments.
It samples suitable primes close to 2^bit_length and returns a vector of `SmallModulus` elements.
- `PlainModulus::Batching(...)` can be used to sample a prime for `plain_modulus` that supports `BatchEncoder` for the BFV scheme.

Other important changes:

- Removed `size_capacity` function and data members from `Ciphertext` class.
- Moved all validation methods such as `is_valid_for` and `is_metadata_valid_for` to `valcheck.h`.
- Removed argument `decomposition_bit_count` from methods `relin_keys(...)` and `galois_keys(...)` in class `KeyGenerator`.
- It is no longer possible to create more than one relinearization key.
This is to simplify the API and reduce confusion. We have never seen a real use-case where more relinearization keys would be a good idea.
- Added methods to generate an encryption of zero to `Encryptor`.
- Added comparison methods and primality check for `SmallModulus`.
- Classes `RelinKeys` and `GaloisKeys` are now derived from a common base class `KSwitchKeys`.
- GoogleTest framework is now included as a Git submodule.
- Numerous bugs have been fixed, particularly in the .NET wrappers.

## Version 3.2

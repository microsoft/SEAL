# Microsoft SEAL

Microsoft SEAL is an easy-to-use open-source ([MIT licensed](LICENSE)) homomorphic encryption library developed by the Cryptography and Privacy Research Group at Microsoft.
Microsoft SEAL is written in modern standard C++ and is easy to compile and run in many different environments.
For more information about the Microsoft SEAL project, see [sealcrypto.org](https://www.microsoft.com/en-us/research/project/microsoft-seal).

This document pertains to Microsoft SEAL version 4.1.
Users of previous versions of the library should look at the [list of changes](CHANGES.md).

## News

The [BGV scheme](https://eprint.iacr.org/2011/277) is now available in Microsoft SEAL.
Implementation details are described in [this paper](https://eprint.iacr.org/2020/1481.pdf).
We truly appreciate [Alibaba Gemini Lab](https://alibaba-gemini-lab.github.io/) for making massive efforts to develop the BGV scheme and integrate it in Microsoft SEAL. And we would like to thank Privacy Technologies Research, Intel Labs, for continuous testing and reporting issues.

Starting from version 3.7.2, Microsoft SEAL will push new changes to the `main`, `master`, and `contrib` branches without creating a new version.
We adopt this approach to merge community contribution and resolve issues in a timely manner.
These branches will stay ahead of the latest version branch/tag.
New versions will be created when there are important bug fixes or new features.

The [EVA compiler for CKKS](https://arxiv.org/abs/1912.11951) is available at [GitHub.com/Microsoft/EVA](https://GitHub.com/Microsoft/EVA). See [CKKS Programming with EVA](#ckks-programming-with-eva) below for more information.

The [SEAL-Embedded for CKKS Encryption](https://tches.iacr.org/index.php/TCHES/article/view/8991) is available at [Github.com/Microsoft/SEAL-Embedded](https://github.com/microsoft/SEAL-Embedded).

The [APSI library for Asymmetric PSI](https://eprint.iacr.org/2021/1116) is available at [Github.com/Microsoft/APSI](https://github.com/microsoft/APSI).

## Contents

- [Introduction](#introduction)
  - [Core Concepts](#core-concepts)
  - [Homomorphic Encryption](#homomorphic-encryption)
  - [Microsoft SEAL](#microsoft-seal-1)
- [Getting Started](#getting-started)
  - [Optional Dependencies](#optional-dependencies)
    - [Intel HEXL](#intel-hexl)
    - [Microsoft GSL](#microsoft-gsl)
    - [ZLIB and Zstandard](#zlib-and-zstandard)
  - [Installing from NuGet Package](#installing-from-nuget-package-windows-linux-macos-android-ios)
  - [Installing from vcpkg](#installing-from-vcpkg)
  - [Examples](#examples)
  - [CKKS Programming with EVA](#ckks-programming-with-eva)
- [Building Microsoft SEAL Manually](#building-microsoft-seal-manually)
  - [Building C++ Components](#building-c-components)
    - [Requirements](#requirements)
    - [Building Microsoft SEAL](#building-microsoft-seal)
    - [Installing Microsoft SEAL](#installing-microsoft-seal)
    - [Building and Installing on Windows](#building-and-installing-on-windows)
    - [Building for Android and iOS](#building-for-android-and-ios)
    - [Building for WebAssembly](#building-for-webassembly)
    - [Basic CMake Options](#basic-cmake-options)
    - [Advanced CMake Options](#advanced-cmake-options)
    - [Linking with Microsoft SEAL through CMake](#linking-with-microsoft-seal-through-cmake)
    - [Examples, Tests, and Benchmarks](#examples-tests-and-benchmarks)
  - [Building .NET Components](#building-net-components)
    - [Windows, Linux, and macOS](#windows-linux-and-macos)
    - [Android and iOS](#android-and-ios)
    - [Using Microsoft SEAL for .NET](#using-microsoft-seal-for-net)
    - [Building Your Own NuGet Package](#building-your-own-nuget-package)
- [Contributing](#contributing)
- [Citing Microsoft SEAL](#citing-microsoft-seal)
- [Acknowledgments](#acknowledgments)

## Introduction

### Core Concepts

Most encryption schemes consist of three functionalities: key generation, encryption, and decryption.
Symmetric-key encryption schemes use the same secret key for both encryption and decryption; public-key encryption schemes use separately a public key for encryption and a secret key for decryption.
Therefore, public-key encryption schemes allow anyone who knows the public key to encrypt data, but only those who know the secret key can decrypt and read the data.
Symmetric-key encryption can be used for efficiently encrypting very large amounts of data, and enables secure outsourced cloud storage.
Public-key encryption is a fundamental concept that enables secure online communication today, but is typically much less efficient than symmetric-key encryption.

While traditional symmetric- and public-key encryption can be used for secure storage and communication, any outsourced computation will necessarily require such encryption layers to be removed before computation can take place.
Therefore, cloud services providing outsourced computation capabilities must have access to the secret keys, and implement access policies to prevent unauthorized employees from getting access to these keys.

### Homomorphic Encryption

Homomorphic encryption refers to encryption schemes that allow the cloud to compute directly on the encrypted data, without requiring the data to be decrypted first.
The results of such encrypted computations remain encrypted, and can be only decrypted with the secret key (by the data owner).
Multiple homomorphic encryption schemes with different capabilities and trade-offs have been invented over the past decade; most of these are public-key encryption schemes, although the public-key functionality may not always be needed.

Homomorphic encryption is not a generic technology: only some computations on encrypted data are possible.
It also comes with a substantial performance overhead, so computations that are already very costly to perform on unencrypted data are likely to be infeasible on encrypted data.
Moreover, data encrypted with homomorphic encryption is many times larger than unencrypted data, so it may not make sense to encrypt, e.g., entire large databases, with this technology.
Instead, meaningful use-cases are in scenarios where strict privacy requirements prohibit unencrypted cloud computation altogether, but the computations themselves are fairly lightweight.

Typically, homomorphic encryption schemes have a single secret key which is held by the data owner.
For scenarios where multiple different private data owners wish to engage in collaborative computation, homomorphic encryption is probably not a reasonable solution.

Homomorphic encryption cannot be used to enable data scientists to circumvent GDPR.
For example, there is no way for a cloud service to use homomorphic encryption to draw insights from encrypted customer data.
Instead, results of encrypted computations remain encrypted and can only be decrypted by the owner of the data, e.g., a cloud service customer.

Most homomorphic encryption schemes provide weaker security guarantees than traditional encryption schemes. You need to read [SECURITY.md](SECURITY.md) if you are thinking of building production software using Microsoft SEAL.

### Microsoft SEAL

Microsoft SEAL is a homomorphic encryption library that allows additions and multiplications to be performed on encrypted integers or real numbers.
Other operations, such as encrypted comparison, sorting, or regular expressions, are in most cases not feasible to evaluate on encrypted data using this technology.
Therefore, only specific privacy-critical cloud computation parts of programs should be implemented with Microsoft SEAL.

It is not always easy or straightforward to translate an unencrypted computation into a computation on encrypted data, for example, it is not possible to branch on encrypted data.
Microsoft SEAL itself has a steep learning curve and requires the user to understand many homomorphic encryption specific concepts, even though in the end the API is not too complicated.
Even if a user is able to program and run a specific computation using Microsoft SEAL, the difference between efficient and inefficient implementations can be several orders of magnitude, and it can be hard for new users to know how to improve the performance of their computation.

Microsoft SEAL comes with two different homomorphic encryption schemes with very different properties.
The BFV and BGV schemes allow modular arithmetic to be performed on encrypted integers.
The CKKS scheme allows additions and multiplications on encrypted real or complex numbers, but yields only approximate results.
In applications such as summing up encrypted real numbers, evaluating machine learning models on encrypted data, or computing distances of encrypted locations CKKS is going to be by far the best choice.
For applications where exact values are necessary, the BFV and BGV schemes are more suitable.

## Getting Started

There are multiple ways of installing Microsoft SEAL and starting to use it.
The easiest way is to use a package manager to download, build, and install the library.
For example, [vcpkg](https://github.com/microsoft/vcpkg) works on most platforms and will be up-to-date with the latest release of Microsoft SEAL (C++17 only).
On macOS you can also use [Homebrew](https://formulae.brew.sh/formula/seal).
On FreeBSD you can use `pkg install seal` to install [security/seal](https://www.freshports.org/security/seal/).
The .NET library is available as a multiplatform [NuGet package](https://www.nuget.org/packages/Microsoft.Research.SEALNet).
Finally, one can build Microsoft SEAL manually with a multiplatform CMake build system; see [Building Microsoft SEAL Manually](#building-microsoft-seal-manually) for details.

### Optional Dependencies

Microsoft SEAL has no required dependencies, but certain optional features can be enabled when compiling with support for specific third-party libraries.

When [building manually](#building-microsoft-seal-manually), one can choose to have the Microsoft SEAL build system download and build the dependencies, or alternatively search the system directories for pre-installed dependencies.
On the other extreme, the downloadable [NuGet package](https://www.nuget.org/packages/Microsoft.Research.SEALNet) cannot be configured at all, but it is always possible to [build a custom NuGet package](#building-your-own-nuget-package).
Other package managers offer varying amounts of opportunities for configuring the dependencies and [other build options](#basic-cmake-options).

The optional dependencies and their tested versions (other versions may work as well) are as follows:

| Optional dependency                                    | Tested version | Use                                              |
| ------------------------------------------------------ | -------------- | ------------------------------------------------ |
| [Intel HEXL](https://github.com/intel/hexl)            | 1.2.5          | Acceleration of low-level kernels                |
| [Microsoft GSL](https://github.com/microsoft/GSL)      | 4.0.0          | API extensions                                   |
| [ZLIB](https://github.com/madler/zlib)                 | 1.2.13         | Compressed serialization                         |
| [Zstandard](https://github.com/facebook/zstd)          | 1.5.2          | Compressed serialization (much faster than ZLIB) |
| [GoogleTest](https://github.com/google/googletest)     | 1.12.1         | For running tests                                |
| [GoogleBenchmark](https://github.com/google/benchmark) | 1.7.1          | For running benchmarks                           |

#### Intel HEXL

Intel HEXL is a library providing efficient implementations of cryptographic primitives common in homomorphic encryption. The acceleration is particularly evident on Intel processors with the Intel AVX512-IFMA52 instruction set.

#### Microsoft GSL

Microsoft GSL (Guidelines Support Library) is a header-only library that implements `gsl::span`: a *view type* that provides safe (bounds-checked) array access to memory.

For example, if Microsoft GSL is available, Microsoft SEAL can allow `BatchEncoder` and `CKKSEncoder` to encode from and decode to a `gsl::span` instead of `std::vector`, which can in some cases have a significant performance benefit.

#### ZLIB and Zstandard

ZLIB and Zstandard are widely used compression libraries. Microsoft SEAL can optionally use these libraries to compress data that is serialized.

One may ask how compression can help when ciphertext and key data is supposed to be indistinguishable from random.
In Microsoft SEAL `Ciphertext` objects consist of a large number of integers modulo specific prime numbers (`coeff_modulus` primes).
When using the CKKS scheme in particular, these prime numbers can be quite small (e.g., 30 bits), but the data is nevertheless serialized as 64-bit integers.
Therefore, it is not uncommon that almost half of the ciphertext bytes are zeros, and applying a general-purpose compression algorithm is a convenient way of getting rid this wasted space.
The BFV scheme benefits typically less from this technique, because the prime numbers used for the `coeff_modulus` encryption parameter tend to be larger, and integers modulo these prime numbers fill more of each 64-bit word.
Compressed serialization can be applied to any serializable Microsoft SEAL object &ndash; not just to `Ciphertext` and keys .

If Microsoft SEAL is compiled with ZLIB or Zstandard support, compression will automatically be used for serialization; see `Serialization::compr_mode_default` in [native/src/seal/serialization.h](native/src/seal/serialization.h).
However, it is always possible to explicitly pass `compr_mode_type::none` to serialization methods to disable compression.
If both ZLIB and Zstandard support are enabled, Zstandard is used by default due to its much better performance.

**Note:** The compression rate for a `SecretKey` can (in theory at least) reveal information about the key.
In most common applications of Microsoft SEAL the size of a `SecretKey` would not be deliberately revealed to untrusted parties.
If this is a concern, one can always save the `SecretKey` in an uncompressed form.

<!-- ### Installing with VCPKG (Windows, Unix-like) -->
<!-- To install Microsoft SEAL with all dependencies enabled, run `./vcpkg install seal` or `./vcpkg install seal:x64-windows-static` on Windows. -->
<!-- To install Microsoft SEAL with partial dependencies enabled, for example, only `ms-gsl`, run `./vcpkg install seal[core,ms-gsl]` or `./vcpkg install seal[core,ms-gsl]:x64-windows-static` on Windows. -->

<!-- ### Installing with Homebrew (macOS) -->

### Installing from NuGet Package (Windows, Linux, macOS, Android, iOS)

For .NET developers the easiest way of installing Microsoft SEAL is by using the multiplatform NuGet package available at [NuGet.org](https://www.nuget.org/packages/Microsoft.Research.SEALNet).
Simply add this package into your .NET project as a dependency and you are ready to go.

To develop mobile applications using Microsoft SEAL and .NET for Android and iOS, just add this package to your [Xamarin](https://dotnet.microsoft.com/apps/xamarin) project. Unlike the Microsoft SEAL C++ library, the .NET wrapper library works only on 64-bit platforms, so only `arm64-v8a`/`x86_64` Android ABIs and `arm64`/`x86_64` iOS architectures are supported.

### Installing from vcpkg

You can download and install seal using the [vcpkg](https://github.com/Microsoft/vcpkg) dependency manager.

```shell
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh  # ./bootstrap-vcpkg.bat for Windows
./vcpkg integrate install
./vcpkg install seal
```

The "seal" port in vcpkg is kept up to date by Microsoft team members and community contributors.
If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.

### Examples

Using Microsoft SEAL will require the user to invest some time in learning fundamental concepts in homomorphic encryption.
The code comes with heavily commented examples that are designed to gradually teach such concepts as well as demonstrate a large fraction of the API.
The examples are available (and identical) in C++ and C#, and are divided into several source files in `native/examples/` (C++) and `dotnet/examples/` (C#), as follows:

| C++                   | C#                   | Description                                                                  |
| --------------------- | -------------------- | ---------------------------------------------------------------------------- |
| `examples.cpp`        | `Examples.cs`        | The example runner application                                               |
| `1_bfv_basics.cpp`    | `1_BFV_Basics.cs`    | Encrypted modular arithmetic using the BFV scheme                            |
| `2_encoders.cpp`      | `2_Encoders.cs`      | Encoding more complex data into Microsoft SEAL plaintext objects             |
| `3_levels.cpp`        | `3_Levels.cs`        | Introduces the concept of levels; prerequisite for using the CKKS scheme     |
| `4_bgv_basics.cpp`    | `4_BGV_Basics.cs`    | Encrypted modular arithmetic using the BGV scheme                            |
| `5_ckks_basics.cpp`   | `5_CKKS_Basics.cs`   | Encrypted real number arithmetic using the CKKS scheme                       |
| `6_rotation.cpp`      | `6_Rotation.cs`      | Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes |
| `7_serialization.cpp` | `7_Serialization.cs` | Serializing objects in Microsoft SEAL                                        |
| `8_performance.cpp`   | `8_Performance.cs`   | Performance tests                                                            |

It is recommended to read the comments and the code snippets along with command line printout from running an example.
For easier navigation, command line printout provides the line number in the associated source file where the associated code snippets start.
To build the examples, see [Examples, Tests, and Benchmark](#examples-tests-and-benchmarks) (C++) and [Building .NET Components](#building-net-components) (C#).

**Note:** It is impossible to know how to use Microsoft SEAL correctly without studying examples 1&ndash;6.
They are designed to provide the reader with the necessary conceptual background on homomorphic encryption.
Reusing code directly from the examples will not work well, as the examples are often demonstrating individual pieces of functionality, and are not optimized for performance.
Writing Microsoft SEAL code without studying the examples in depth will inevitably result in code that is vulnerable, malfunctioning, or extremely slow.

### CKKS Programming with EVA

When studying the examples above, it will become clear that the CKKS scheme can be unfriendly to beginners.
Even relatively simple computations can be challenging to get to work due to the limitations of the rescaling operation and the requirement of aligning scales at different levels.

We have created a new compiler tool called EVA that helps resolve these challenges to a large extent.
EVA allows programmers to express desired encrypted computations in Python. It optimizes the computations for Microsoft SEAL, selects appropriate encryption parameters, and provides a convenient Python API for encrypting the input, executing the computation, and decrypting the result.
EVA is available at [GitHub.com/Microsoft/EVA](https://GitHub.com/Microsoft/EVA).
Try it out, and let us know what you think!

**Note:** EVA only supports the CKKS scheme. There are no immediate plans to support the BFV or BGV scheme.

## Building Microsoft SEAL Manually

### Building C++ Components

On all platforms Microsoft SEAL is built with CMake.
We recommend using out-of-source build although in-source build works.
Below we give instructions for how to configure, build, and install Microsoft SEAL either globally (system-wide), or locally (for a single user).
A global install requires elevated (root or administrator) privileges.

#### Requirements

| System | Toolchain |
|---|---|
| Windows | Visual Studio 2022 with C++ CMake Tools for Windows |
| Linux | Clang++ (>= 5.0) or GNU G++ (>= 6.0), CMake (>= 3.13) |
| macOS/iOS | Xcode toolchain (>= 9.3), CMake (>= 3.13) |
| Android | Android Studio |
| FreeBSD | CMake (>= 3.13) |

**Note:** Microsoft SEAL compiled with Clang++ has much better runtime performance than one compiled with GNU G++.

#### Building Microsoft SEAL

We assume that Microsoft SEAL has been cloned into a directory called `SEAL` and all commands presented below are assumed to be executed in the directory `SEAL`.

You can build the Microsoft SEAL library (out-of-source) for your machine by executing the following commands:

```PowerShell
cmake -S . -B build
cmake --build build
```

After the build completes, the output binaries can be found in `build/lib/` and `build/bin/` directories.

Various configuration options can be specified and passed to the CMake build system.
These are described below in sections [Basic CMake Options](#basic-cmake-options) and [Advanced CMake Options](#advanced-cmake-options).

#### Installing Microsoft SEAL

If you have root access to the system you can install Microsoft SEAL globally as follows:

```PowerShell
cmake -S . -B build
cmake --build build
sudo cmake --install build
```

To instead install Microsoft SEAL locally, e.g., to `~/mylibs/`, do the following:

```PowerShell
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=~/mylibs
cmake --build build
sudo cmake --install build
```

#### Building and Installing on Windows

On Windows the same scripts above work in a developer command prompt for Visual Studio using either the Ninja or "Visual Studio 17 2022" generators.

When using the Ninja generator, please use the appropriate command prompt depending on the platform you want to build for. If you want to build for x64, please use the **x64 Native Tools Command Prompt for Visual Studio 2022** command prompt to configure and build the library. If you want to build for x86, please use the **x86 Native Tools Command Prompt for Visual Studio 2022** command prompt to configure and build the library. To build using Ninja, type

```PowerShell
cmake -S . -B build -G Ninja
cmake --build build
```

When using the "Visual Studio 17 2022" generator you can use the **Developer Command Prompt for VS 2022** command prompt to configure and build the library. By default the generated platform will be x64. You can specify the desired platform using the architecture flag `-A <x64|Win32>` and the desired configuration using `--config <Debug|Release>`.

```PowerShell
# Generate and build for x64 in Release mode
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

```PowerShell
# Generate and build for x86 in Release mode
cmake -S . -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release
```

Installing the library in Windows works as well. Instead of using the `sudo` command, however, you need to run `cmake --install build` from a command prompt with Administrator permissions. Files will be installed by default to `C:\Program Files (x86)\SEAL\`.

Visual Studio 2022 provides support for CMake-based projects. You can select the menu option `File / Open / Folder...` and navigate to the folder where the Microsoft SEAL repository is located. After opening the folder, Visual Studio will detect that this is a CMake-based project and will enable the menu command `Project / CMake settings for SEAL`. This will open the CMake settings editor that provides a user interface where you can create different configurations and set different CMake options.

After the build completes, the output static library `seal-<version>.lib` can be found in `build\lib\` or `build\lib\Release\`.
When linking with applications, using CMake as is explained in [Linking with Microsoft SEAL through CMake](#linking-with-microsoft-seal-through-cmake) is highly recommended.
Alternatively, you need to add `native\src\` (full path) and `build\native\src\` as include directories to locate the Microsoft SEAL header files.

#### Building for Android and iOS

Microsoft SEAL can be compiled for Android and iOS.
Under the [android/](android/) directory of the source tree you will find an [Android Studio](https://developer.android.com/studio) project that you can use to compile the library for Android.

To build the library for iOS, use the following scripts:

```PowerShell
# Configure CMake
cmake -S . -B build -GXcode -DSEAL_BUILD_SEAL_C=ON -DSEAL_BUILD_STATIC_SEAL_C=ON -DCMAKE_SYSTEM_NAME=iOS "-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64" -C cmake/memset_s.iOS.cmake

# Build libseal*.a for x86_64
xcodebuild -project build/SEAL.xcodeproj -sdk iphonesimulator -arch x86_64 -configuration Release clean build
mkdir -p build/lib/x86_64
cp build/lib/Release/libseal*.a build/lib/x86_64

# Build libseal*.a for arm64
xcodebuild -project SEAL.xcodeproj -sdk iphoneos -arch arm64 -configuration Release clean build
mkdir -p build/lib/arm64
cp build/lib/Release/libseal*.a build/lib/arm64

# Combine libseal-*.a into libseal.a and libsealc-*.a into libsealc.a
lipo -create -output build/lib/libseal.a build/lib/x86_64/libseal-*.a arm64/libseal-*.a
lipo -create -output build/lib/libsealc.a build/lib/x86_64/libsealc-*.a build/lib/arm64/libsealc-*.a
```

The native libraries generated through these methods are meant to be called only through the .NET library described in the following sections.
Specifically, they do not contain any wrappers that can be used from Java (for Android) or Objective C (for iOS).

#### Building for WebAssembly

Microsoft SEAL can be compiled for JavaScript and WebAssembly using [emscripten](https://emscripten.org) on Windows, Linux, and macOS.
Building for the Web means SEAL can be run in any client/server environment such as all the major browsers (e.g. Edge, Chrome, Firefox, Safari) and NodeJS.

Building for WebAssembly requires the emscripten toolchain to be installed.
The easiest way to configure the toolchain is to clone [emsdk](https://github.com/emscripten-core/emsdk) and follow the [instructions](https://emscripten.org/docs/getting_started/downloads.html#installation-instructions-using-the-emsdk-recommended) (with system-specific notes). For examples, on Linux and macOS, inside the `emsdk` repo, run the following:

```PowerShell
# Install the latest toolchain
./emsdk install latest
./emsdk activate latest
# Source the environment
source ./emsdk_env.sh
```
**On Windows, better run from a developer command prompt for Visual Studio; and replace `./emsdk` and `source ./emsdk_env.sh` with `emsdk` and `emsdk_env.bat`, respectively.**
In other environments, `cmake` must be added to the path, and either "Ninja" or "MinGW Makefiles" should be specified as generator in the following configuration step.
`emcmake` does not work with Visual Studio 17 2022 generator.

Within the same shell, navigate to the root directory of Microsoft SEAL, run the following commands to build for WebAssembly:

```PowerShell
# Configure CMake. Example flags for a release build
emcmake cmake -S . -B build \
 -DBUILD_SHARED_LIBS=OFF \
 -DCMAKE_BUILD_TYPE=Release \
 -DCMAKE_CXX_FLAGS_RELEASE="-DNDEBUG -flto -O3" \
 -DCMAKE_C_FLAGS_RELEASE="-DNDEBUG -flto -O3" \
 -DSEAL_BUILD_BENCH=OFF \ # Benchmark can be built for WASM. Change this to ON.
 -DSEAL_BUILD_EXAMPLES=OFF \
 -DSEAL_BUILD_TESTS=OFF \
 -DSEAL_USE_CXX17=ON \
 -DSEAL_USE_INTRIN=ON \
 -DSEAL_USE_MSGSL=OFF \
 -DSEAL_USE_ZLIB=ON \
 -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=ON

# Make the static library (shared libs are not supported with emscripten)
emmake make -C build -j

# Build the WebAssembly module
emcc \
 -Wall \
 -flto \
 -O3 \
 build/lib/libseal-4.1.a \
 --bind \
 -o "build/bin/seal_wasm.js" \
 -s WASM=1 \
 -s ALLOW_MEMORY_GROWTH=1
```

**Note**: There are many flags to consider when building a WebAssembly module. Please refer to the [settings.js](https://github.com/emscripten-core/emscripten/blob/main/src/settings.js) file for advanced build flags.

Building will generate two output files, `seal_wasm.js` and `seal_wasm.wasm`, in the `build/bin/` directory.
The file sizes for the artifacts are very small.
This is because that the optimization flags perform dead code elimination (DCE) as there are no bindings generated to JavaScript.
Defining these bindings is **necessary** in order to call into WebAssembly from the JavaScript domain; however, Microsoft SEAL does not include any definitions at this time.
The build flag `--bind` expects the bindings to be specified using the [embind](https://emscripten.org/docs/porting/connecting_cpp_and_javascript/embind.html) syntax.

#### Basic CMake Options

The following options can be used with CMake to configure the build. The default value for each option is denoted with boldface in the **Values** column.

| CMake option           | Values                                                       | Information                                                                                                                                                                                            |
| ---------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CMAKE_BUILD_TYPE       | **Release**</br>Debug</br>RelWithDebInfo</br>MinSizeRel</br> | `Debug` and `MinSizeRel` have worse run-time performance. `Debug` inserts additional assertion code. Set to `Release` unless you are developing Microsoft SEAL itself or debugging some complex issue. |
| SEAL_BUILD_EXAMPLES    | ON / **OFF**                                                 | Build the C++ examples in [native/examples](native/examples).                                                                                                                                          |
| SEAL_BUILD_TESTS       | ON / **OFF**                                                 | Build the tests to check that Microsoft SEAL works correctly.                                                                                                                                          |
| SEAL_BUILD_BENCH       | ON / **OFF**                                                 | Build the performance benchmark.                                                                                                                                                                       |
| SEAL_BUILD_DEPS        | **ON** / OFF                                                 | Set to `ON` to automatically download and build [optional dependencies](#optional-dependencies); otherwise CMake will attempt to locate pre-installed dependencies.                                    |
| SEAL_USE_INTEL_HEXL    | ON / **OFF**                                                 | Set to `ON` to use Intel HEXL for low-level kernels.                                                                                                                                            |
| SEAL_USE_MSGSL         | **ON** / OFF                                                 | Build with Microsoft GSL support.                                                                                                                                                                      |
| SEAL_USE_ZLIB          | **ON** / OFF                                                 | Build with ZLIB support.                                                                                                                                                                               |
| SEAL_USE_ZSTD          | **ON** / OFF                                                 | Build with Zstandard support.                                                                                                                                                                          |
| BUILD_SHARED_LIBS      | ON / **OFF**                                                 | Set to `ON` to build a shared library instead of a static library. Not supported in Windows.                                                                                                           |
| SEAL_BUILD_SEAL_C      | ON / **OFF**                                                 | Build the C wrapper library SEAL_C. This is used by the C# wrapper and most users should have no reason to build it.                                                                                   |
| SEAL_USE_CXX17         | **ON** / OFF                                                 | Set to `ON` to build Microsoft SEAL as C++17 for a positive performance impact.                                                                                                                        |
| SEAL_USE_INTRIN        | **ON** / OFF                                                 | Set to `ON` to use compiler intrinsics for improved performance. CMake will automatically detect which intrinsics are available and enable them accordingly.                                           |

As usual, these options can be passed to CMake with the `-D` flag.
For example, one could run

```PowerShell
cmake -S . -B build -DSEAL_BUILD_EXAMPLES=ON
```

to configure a release build of a static Microsoft SEAL library and also build the examples.

#### Advanced CMake Options

The following options can be used with CMake to further configure the build. Most users should have no reason to change these, which is why they are marked as advanced.

| CMake option                         | Values                    | Information                                                                                                                                                                                                                                                                                              |
| ------------------------------------ | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT | **ON** / OFF              | Set to `ON` to throw an exception when Microsoft SEAL produces a ciphertext with no key-dependent component. For example, subtracting a ciphertext from itself, or multiplying a ciphertext with a plaintext zero yield identically zero ciphertexts that should not be considered as valid ciphertexts. |
| SEAL_BUILD_STATIC_SEAL_C             | ON / **OFF**              | Set to `ON` to build SEAL_C as a static library instead of a shared library.                                                                                                                                                                                                                             |
| SEAL_DEFAULT_PRNG                    | **Blake2xb**</br>Shake256 | Microsoft SEAL supports both Blake2xb and Shake256 XOFs for generating random bytes. Blake2xb is much faster, but it is not standardized, whereas Shake256 is a FIPS standard.                                                                                                                           |
| SEAL_USE_GAUSSIAN_NOISE              | ON / **OFF**              | Set to `ON` to use a non-constant time rounded continuous Gaussian for the error distribution; otherwise a centered binomial distribution &ndash; with slightly larger standard deviation &ndash; is used.                                                                                               |
| SEAL_AVOID_BRANCHING                 | ON / **OFF**              | Set to `ON` to eliminate branching in critical functions when compiler has maliciously inserted flags; otherwise assume `cmov` is used.                                                                                               |
| SEAL_SECURE_COMPILE_OPTIONS          | ON / **OFF**              | Set to `ON` to compile/link with Control-Flow Guard (`/guard:cf`) and Spectre mitigations (`/Qspectre`). This has an effect only when compiling with MSVC.                                                                                                                                               |
| SEAL_USE_ALIGNED_ALLOC                    | **ON** / OFF              | Set to `ON` to use 64-byte aligned memory allocations. This can improve performance of AVX512 primitives when Intel HEXL is enabled. This depends on C++17 and is disabled on Android.                                                                                               |

#### Linking with Microsoft SEAL through CMake

It is very easy to link your own applications and libraries with Microsoft SEAL if you use CMake.
Simply add the following to your `CMakeLists.txt`:

```PowerShell
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(<your target> SEAL::seal)
```

If Microsoft SEAL was installed globally, the above `find_package` command will likely find the library automatically.
To link with a Microsoft SEAL installed locally, e.g., installed in `~/mylibs` as described above, you may need to tell CMake where to look for Microsoft SEAL when you configure your application by running:

```PowerShell
cd <directory containing your CMakeLists.txt>
cmake . -DCMAKE_PREFIX_PATH=~/mylibs
```

If Microsoft SEAL was installed using a package manager like vcpkg or Homebrew, please refer to their documentation for how to link with the installed library. For example, vcpkg requires you to specify the vcpkg CMake toolchain file when configuring your project.

#### Examples, Tests, and Benchmarks

When building Microsoft SEAL, examples, tests, and benchmarks can be built by setting `SEAL_BUILD_EXAMPLES=ON`, `SEAL_BUILD_TESTS=ON`, and `SEAL_BUILD_BENCH=ON`; see [Basic CMake Options](basic-cmake-options).
Alternatively, [examples](native/examples/CMakeLists.txt), [tests](native/tests/CMakeLists.txt), and [benchmark](native/bench/CMakeLists.txt) can be built as standalone CMake projects linked with Microsoft SEAL (installed in `~/mylibs`), by following the commands below.
Omit setting `SEAL_ROOT` if the library is installed globally.

```PowerShell
cd native/<examples|tests|bench>
cmake -S . -B build -DSEAL_ROOT=~/mylibs
cmake --build build
```

By default, benchmarks run for a vector of parameters and primitives, which can be overwhelmingly informative.
To execute a subset of benchmark cases, see [Google Benchmark README](https://github.com/google/benchmark/blob/master/README.md#running-a-subset-of-benchmarks).
For advanced users, the `bm_parms_vec` variable in [native/bench/bench.cpp](native/bench/bench.cpp) can be overwritten with custom parameter sets.

**Note**: The benchmark code is strictly for experimental purposes; it allows insecure parameters that must not be used in real applications.
Do not follow the benchmarks as examples.

### Building .NET Components

Microsoft SEAL provides a .NET Standard library that wraps the functionality in Microsoft SEAL for use in .NET development.
Using the existing [NuGet package](https://www.nuget.org/packages/Microsoft.Research.SEALNet) is highly recommended, unless development of Microsoft SEAL or building a custom NuGet package is intended.
Prior to building .NET components, the C wrapper library SEAL_C must be built following [Building C++ Components](#building-c-components).
The SEAL_C library is meant to be used only by the .NET library, not by end-users.

**Note**: SEAL_C and the .NET library only support 64-bit platforms.

#### Windows, Linux, and macOS

For compiling .NET code you will need to install a [.NET SDK (>= 6.0)](https://dotnet.microsoft.com/download).
Building the SEAL_C library with CMake will generate project files for the .NET wrapper library, examples, and unit tests.
The SEAL_C library must be discoverable when running a .NET application, e.g., be present in the same directory as your executable, which is taken care of by the .NET examples and tests project files.
Run the following scripts to build each project:

```PowerShell
dotnet build build/dotnet/src --configuration <Debug|Release> # Build .NET wrapper library
dotnet test build/dotnet/tests # Build and run .NET unit tests
dotnet run -p build/dotnet/examples # Build and run .NET examples
```

You can use `--configuration <Debug|Release>` to run `Debug` or `Release` examples and unit tests.
You can use `--verbosity detailed` to print the list of unit tests that are being run.

On Windows, you can also use the Microsoft Visual Studio 2022 solution file, for example, `out/build/x64-Debug/dotnet/SEALNet.sln` to build all three projects.

#### Android and iOS

While it is possible to build your own custom NuGet package for Android or iOS (see [Building for Android and iOS](#building-for-android-and-ios) for the native component), this is not easy and is not recommended. Instead, please add a reference to the multiplatform [NuGet package](https://www.nuget.org/packages/Microsoft.Research.SEALNet) to your [Xamarin](https://dotnet.microsoft.com/apps/xamarin) project.

#### Using Microsoft SEAL for .NET

To use Microsoft SEAL for .NET in your own application you need to:

1. Add a reference in your project to `SEALNet.dll`;
1. Ensure the native shared library is available for your application when run.
The easiest way to ensure this is to copy the native shared library to the same directory where your application's executable is located.

#### Building Your Own NuGet Package

You can build your own NuGet package for Microsoft SEAL by following the instructions in [NUGET.md](dotnet/nuget/NUGET.md).

## Contributing

For contributing to Microsoft SEAL, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Citing Microsoft SEAL

To cite Microsoft SEAL in academic papers, please use the following BibTeX entries.

### Version 4.1

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 4.1)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = jan,
        year = 2023,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 4.0

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 4.0)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = mar,
        year = 2022,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.7

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.7)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = sep,
        year = 2021,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.6

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.6)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = nov,
        year = 2020,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.5

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.5)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = apr,
        year = 2020,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.4

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.4)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = oct,
        year = 2019,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.3

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.3)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = jun,
        year = 2019,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.2

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.2)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = feb,
        year = 2019,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.1

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.1)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = dec,
        year = 2018,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

### Version 3.0

```tex
    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.0)},
        howpublished = {\url{http://sealcrypto.org}},
        month = oct,
        year = 2018,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }
```

## Acknowledgments

Many people have contributed substantially to Microsoft SEAL without being represented in the Git history.
We wish to express special gratitude to [John Wernsing](https://github.com/wernsingj), [Hao Chen](https://github.com/haochenuw), [Yongsoo Song](https://yongsoosong.github.io), [Olli Saarikivi](https://github.com/olsaarik), [Rachel Player](https://github.com/rachelplayer), [Gizem S. Cetin](https://github.com/gizemscetin), [Peter Rindal](https://github.com/ladnir), [Amir Jalali](https://github.com/amirjalali65), [Kyoohyung Han](https://github.com/KyoohyungHan), [Sadegh Riazi](https://www.sadeghr.com), [Ilia Iliashenko](https://homes.esat.kuleuven.be/~ilia), [Roshan Dathathri](https://roshandathathri.github.io), [Pardis Emami-Naeini](https://homes.cs.washington.edu/~pemamina), [Sangeeta Chowdhary](https://github.com/sangeeta0201), [Deepika Natarajan](https://github.com/dnat112), and [Michael Rosenberg](https://github.com/rozbb).

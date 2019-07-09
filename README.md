# Microsoft SEAL

Microsoft SEAL is an easy-to-use open-source ([MIT licensed](LICENSE)) homomorphic encryption library developed by the Cryptography Research group at Microsoft. Microsoft SEAL is written in modern standard C++ and has no external dependencies, making it easy to compile and run in many different environments. For more information about the Microsoft SEAL project, see [sealcrypto.org](https://www.microsoft.com/en-us/research/project/microsoft-seal).

This document pertains to Microsoft SEAL version 3.3. Users of previous versions of the library should look at the [list of changes](Changes.md).

# Contents
- [Introduction](#introduction)
  - [Core Concepts](#core-concepts)
  - [Homomorphic Encryption](#homomorphic-encryption)
  - [Microsoft SEAL](#microsoft-seal-1)
- [Installing Microsoft SEAL](#installing-microsoft-seal)
  - [Windows](#windows)
  - [Linux and macOS](#linux-and-macos)
- [Installing Microsoft SEAL for .NET](#installing-microsoft-seal-for-net)
  - [Windows](#windows-1)
  - [Linux and macOS](#linux-and-macos-1)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Citing Microsoft SEAL](#citing-microsoft-seal)

# Introduction
## Core Concepts
Most encryption schemes consist of three functionalities: key generation, encryption, and decryption. Symmetric-key encryption schemes use the same secret key for both encryption and decryption; public-key encryption schemes use separately a public key for encryption and a secret key for decryption. Therefore, public-key encryption schemes allow anyone who knows the public key to encrypt data, but only those who know the secret key can decrypt and read the data. Symmetric-key encryption can be used for efficiently encrypting very large amounts of data, and enables secure outsourced cloud storage. Public-key encryption is a fundamental concept that enables secure online communication today, but is typically much less efficient than symmetric-key encryption.

While traditional symmetric- and public-key encryption can be used for secure storage and communication, any outsourced computation will necessarily require such encryption layers to be removed before computation can take place. Therefore, cloud services providing outsourced computation capabilities must have access to the secret keys, and implement access policies to prevent unauthorized employees from getting access to these keys.

## Homomorphic Encryption
Homomorphic encryption refers to encryption schemes that allow the cloud to compute directly on the encrypted data, without requiring the data to be decrypted first. The results of such encrypted computations remain encrypted, and can be only decrypted with the secret key (by the data owner). Multiple homomorphic encryption schemes with different capabilities and trade-offs have been invented over the past decade; most of these are public-key encryption schemes, although the public-key functionality may not always be needed.

Homomorphic encryption is not a generic technology: only some computations on encrypted data are possible. It also comes with a substantial performance overhead, so computations that are already very costly to perform on unencrypted data are likely to be infeasible on encrypted data. Moreover, data encrypted with homomorphic encryption is many times larger than unencrypted data, so it may not make sense to encrypt, e.g., entire large databases, with this technology. Instead, meaningful use-cases are in scenarios where strict privacy requirements prohibit unencrypted cloud computation altogether, but the computations themselves are fairly lightweight.

Typically, homomorphic encryption schemes have a single secret key which is held by the data owner. For scenarios where multiple different private data owners wish to engage in collaborative computation, homomorphic encryption is probably not a reasonable solution.

Homomorphic encryption cannot be used to enable data scientist to circumvent GDPR. For example, there is no way for a cloud service to use homomorphic encryption to draw insights from encrypted customer data. Instead, results of encrypted computations remain encrypted and can only be decrypted by the owner of the data, e.g., a cloud service customer.

## Microsoft SEAL
Microsoft SEAL is a homomorphic encryption library that allows additions and multiplications to be performed on encrypted integers or real numbers. Other operations, such as encrypted comparison, sorting, or regular expressions, are in most cases not feasible to evaluate on encrypted data using this technology. Therefore, only specific privacy-critical cloud computation parts of programs should be implemented with Microsoft SEAL.

It is not always easy or straightfoward to translate an unencrypted computation into a computation on encrypted data, for example, it is not possible to branch on encrypted data. Microsoft SEAL itself has a steep learning curve and requires the user to understand many homomorphic encryption specific concepts, even though in the end the API is not too complicated. Even if a user is able to program and run a specific computation using Microsoft SEAL, the difference between efficient and inefficient implementations can be several orders of magnitude, and it can be hard for new users to know how to improve the performance of their computation.

Microsoft SEAL comes with two different homomorphic encryption schemes with very different properties. The BFV scheme allows modular arithmetic to be performed on encrypted integers. The CKKS scheme allows additions and multiplications on encrypted real or complex numbers, but yields only approximate results. In applications such a summing up encrypted real numbers, evaluating machine learning models on encrypted data, or computing distances of encrypted locations CKKS is going to be by far the best choice. For applications where exact values are necessary, the BFV scheme is the only choice.

# Installing Microsoft SEAL

## Windows

Microsoft SEAL comes with a Microsoft Visual Studio 2017 solution file `SEAL.sln` that can be
used to conveniently build the library, examples, and unit tests.

#### Debug and Release builds

You can easily switch from Visual Studio build configuration menu whether Microsoft SEAL should be
built in `Debug` mode (no optimizations) or in `Release` mode. Please note that `Debug`
mode should not be used except for debugging SEAL itself, as the performance will be
orders of magnitude worse than in `Release` mode.

#### Library

Build the SEAL project `native\src\SEAL.vcxproj` from `SEAL.sln`. This results
in the static library `seal.lib` to be created in `native\lib\$(Platform)\$(Configuration)`. When
linking with applications, you need to add `native\src\` (full path) as an include directory
for SEAL header files.

#### Examples

Build the SEALExamples project `native\examples\SEALExamples.vcxproj` from `SEAL.sln`.
This results in an executable `sealexamples.exe` to be created in `native\bin\$(Platform)\$(Configuration)`.

#### Unit tests

The unit tests require the Google Test framework to be installed. The appropriate
NuGet package is already listed in `native\tests\packages.config`, so once you attempt to build
the SEALTest project `native\tests\SEALTest.vcxproj` from `SEAL.sln` Visual Studio will
automatically download and install it for you.

## Linux and macOS

Microsoft SEAL is very easy to configure and build in Linux and macOS using CMake (>= 3.10).
A modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0) is needed. In macOS the
Xcode toolchain (>= 9.3) will work.

In macOS you will need CMake with command line tools. For this, you can either
1. install the cmake package with [Homebrew](https://brew.sh), or
2. download CMake directly from [https://cmake.org/download](https://cmake.org/download) and [enable command line tools](https://stackoverflow.com/questions/30668601/installing-cmake-command-line-tools-on-a-mac).

Below we give instructions for how to configure, build, and install SEAL either
system-wide (global install), or for a single user (local install). A system-wide
install requires elevated (root) privileges.

#### Debug and Release builds

You can easily switch from CMake configuration options whether Microsoft SEAL should be built in
`Debug` mode (no optimizations) or in `Release` mode. Please note that `Debug` mode should not
be used except for debugging Microsoft SEAL itself, as the performance will be orders of magnitude
worse than in `Release` mode.

### Global install

#### Library

If you have root access to the system you can install Microsoft SEAL system-wide as follows:
````
cd native/src
cmake .
make
sudo make install
cd ../..
````
#### Examples

To build the examples do:
````
cd native/examples
cmake .
make
cd ../..
````

After completing the above steps the `sealexamples` executable can be found in `native/bin/`.
See `native/examples/CMakeLists.txt` for how to link Microsoft SEAL with your own project using CMake.

#### Unit tests

To build the unit tests you will need the [GoogleTest](https://github.com/google/googletest) framework, which is included in Microsoft SEAL as a git submodule. To download the GoogleTest source files, do:
````
git submodule update --init
````
This needs to be executed only once, and can be skipped if Microsoft SEAL was cloned with `git --recurse-submodules`. To build the tests, do:
````
cd native/tests
cmake .
make
cd ../..
````

After completing these steps the `sealtest` executable can be found in `native/bin/`. All unit
tests should pass successfully.

### Local install

#### Library

To install Microsoft SEAL locally, e.g., to `~/mylibs/`, do the following:
````
cd native/src
cmake -DCMAKE_INSTALL_PREFIX=~/mylibs .
make
make install
cd ../..
````

#### Examples

To build the examples do:
````
cd native/examples
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

After completing the above steps the `sealexamples` executable can be found in `native/bin/`.
See `native/examples/CMakeLists.txt` for how to link Microsoft SEAL with your own project using CMake.

#### Unit tests

To build the unit tests you will need the [GoogleTest](https://github.com/google/googletest) framework, which is included in Microsoft SEAL as a git submodule. To download the GoogleTest source files, do:
````
git submodule update --init
````
This needs to be executed only one, and can be skipped if Microsoft SEAL was cloned with `git --recurse-submodules`. Then do:
````
cd native/tests
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

After completing these steps the `sealtest` executable can be found in `native/bin/`. All unit
tests should pass successfully.

# Installing Microsoft SEAL for .NET

Microsoft SEAL provides a .NET Standard library that wraps the functionality in Microsoft SEAL
for use in .NET development.

## Windows

The Microsoft Visual Studio 2017 solution file `SEAL.sln` contains the projects necessary
to build the .NET assembly, a backing native shared library, .NET examples, and unit tests.

#### Native library

Microsoft SEAL for .NET requires a native library that is invoked by the managed .NET library.
Build the SEALNetNative project `dotnet\native\SEALNetNative.vcxproj` from `SEAL.sln`.
Building SEALNetNative results in the dynamic library `sealnetnative.dll` to be created
in `dotnet\lib\$(Platform)\$(Configuration)`. This library is meant to be used only by the
.NET library, not by end users, and needs to be present in the same directory as your
executable when developing a .NET application.

#### .NET library

Once you have built the shared native library (see above), build the SEALNet project
`dotnet\src\SEALNet.csproj` from `SEAL.sln`. Building SEALNet results in the assembly
`SEALNet.dll` to be created in `dotnet\lib\$(Configuration)\netstandard2.0`. This
is the assembly you can reference in your application.

#### .NET examples

Build the SEALNetExamples project `dotnet\examples\SEALNetExamples.csproj` from `SEAL.sln`.
This results in the assembly `SEALNetExamples.dll` to be created in
`dotnet\bin\$(Configuration)\netcoreapp2.1`. The project takes care of copying the
native SEALNetNative library to the output directory.

#### .NET unit tests

Build the SEALNet Test project `dotnet\tests\SEALNetTest.csproj` from `SEAL.sln`. This results
in the `SEALNetTest.dll` assembly to be created in `dotnet\lib\$(Configuration)\netcoreapp2.1`.
The project takes care of copying the native SEALNetNative library to the output directory.

### Using Microsoft SEAL for .NET in your own application

To use Microsoft SEAL for .NET in your own application you need to:
1. add a reference in your project to `SEALNet.dll`;
2. ensure `sealnetnative.dll` is available for your application when run. The easiest way to ensure
   this is to copy `sealnetnative.dll` to the same directory where your application's executable
   is located.

Alternatively, you can build and use a NuGet package; see instructions in [NUGET.md](dotnet/nuget/NUGET.md).

## Linux and macOS

Microsoft SEAL for .NET relies on a native shared library that can be easily configured and built
using CMake (>= 3.10) and a modern version of GNU G++ (>= 6.0) or Clang++ (>= 5.0). In macOS
the Xcode toolchain (>= 9.3) will work.

For compiling .NET code you will need to install a .NET Core SDK (>= 2.1). You can follow
these [instructions for installing in Linux](https://dotnet.microsoft.com/download?initial-os=linux),
or for [installing in macOS](https://dotnet.microsoft.com/download?initial-os=macos).

### Local use of shared native library

If you only intend to run the examples and unit tests provided with Microsoft SEAL,
you do not need to install the native shared library, you only need to compile it.
The SEALNetExamples and SEALNetTest projects take care of copying the native shared
library to the appropriate assembly output directory.

To compile the native shared library you will need to:
1. Compile Microsoft SEAL as a static or shared library with Position-Independent Code (PIC);
2. Compile native shared library.

The instructions for compiling Microsoft SEAL are similar to the instructions described
[above](#linux-and-macos) for a global or local install. Make sure the CMake configuration
option `SEAL_LIB_BUILD_TYPE` is set to either `Static_PIC` (default) or `Shared`. Assuming
Microsoft SEAL was built and installed globally using the default CMake configuration
options, we can immediately use it to compile the shared native library required for .NET:
````
cd dotnet/native
cmake .
make
cd ../..
````
If Microsoft SEAL was installed locally instead, use:
````
cd dotnet/native
cmake -DCMAKE_PREFIX_PATH=~/mylibs .
make
cd ../..
````

#### .NET library

To build the .NET Standard library, do the following:
````
cd dotnet/src
dotnet build
cd ../..
````
You can use the `dotnet` parameter `--configuration <Debug|Release>` to build either
a `Debug` or `Release` version of the assembly. This will result in a `SEALNet.dll`
assembly to be created in `dotnet/lib/$(Configuration)/netstandard2.0`. This assembly
is the one you will want to reference in your own projects.

#### Examples

To build and run the .NET examples, do:
````
cd dotnet/examples
dotnet run
cd ../..
````
As mentioned before, the .NET project will copy the shared native library to the assembly
output directory. You can use the `dotnet` parameter `--configuration <Debug|Release>` to
run either `Debug` or `Release` versions of the examples.

#### Unit tests

To build and run the .NET unit tests, do:
````
cd dotnet/tests
dotnet test
cd ../..
````
All unit tests should pass. You can use the `dotnet` parameter `--configuration <Debug|Release>`
to run `Debug` or `Relase` unit tests, and you can use `--verbosity detailed` to print the list
of unit tests that are being run.

### Using Microsoft SEAL for .NET in your own application

To use Microsoft SEAL for .NET in your own application you need to:
1. add a reference in your project to `SEALNet.dll`;
2. ensure the native shared library is available for your application when run. The easiest way to ensure this is to copy `libsealnetnative.so` to the same directory where your application's executable is located.

In Linux or macOS, if you have root access to the system, you have the option to install the
native shared library globally. Then your application will always be able to find and load it.

Assuming Microsoft SEAL is build and installed globally, you can install the shared native
library globally as follows:
````
cd dotnet/native
cmake  .
make
sudo make install
cd ../..
````

# Getting Started
Using Microsoft SEAL will require the user to invest some time in learning fundamental
concepts in homomorphic encryption. The code comes with heavily commented examples that
are designed to gradually teach such concepts as well as to demonstrate much of the API.
The code examples are available (and identical) in C++ and C#, and are divided into
several source files in `native/examples/` (C++) and `dotnet/examples/` (C#), as follows:

|C++                |C#                |Description                                                                 |
|-------------------|------------------|----------------------------------------------------------------------------|
|`examples.cpp`     |`Examples.cs`     |The example runner application                                              |
|`1_bfv_basics.cpp` |`1_BFV_Basics.cs` |Encrypted modular arithmetic using the BFV scheme                           |
|`2_encoders.cpp`   |`2_Encoders.cs`   |Encoding more complex data into Microsoft SEAL plaintext objects            |
|`3_levels.cpp`     |`3_Levels.cs`     |Introduces the concept of levels; prerequisite for using the CKKS scheme    |
|`4_ckks_basics.cpp`|`4_CKKS_Basics.cs`|Encrypted real number arithmetic using the CKKS scheme                      |
|`5_rotation.cpp`   |`5_Rotation.cs`   |Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes|
|`6_performance.cpp`|`6_Performance.cs`|Performance tests for Microsoft SEAL                                        |

It is recommeded to read the comments and the code snippets along with command line printout
from running an example. For easier navigation, command line printout provides the line number
in the associated source file where the associated code snippets start.

**WARNING: It is impossible to use Microsoft SEAL correctly without reading all examples 
or by simply re-using the code from examples. Any developer attempting to do so
will inevitably produce code that is *vulnerable*, *malfunctioning*, or *extremely slow*.**

# Contributing

This project welcomes contributions and suggestions. Most contributions require you
to agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow
the instructions provided by the bot. You will only need to do this once across all
repos using our CLA.

Pull requests must be submitted to the branch called `contrib`.

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.

# Citing Microsoft SEAL

To cite Microsoft SEAL in academic papers, please use the following BibTeX entries.

### Version 3.3

    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.3)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = june,
        year = 2019,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }

### Version 3.2

    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.2)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = feb,
        year = 2019,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }

### Version 3.1

    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.1)},
        howpublished = {\url{https://github.com/Microsoft/SEAL}},
        month = dec,
        year = 2018,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }

### Version 3.0

    @misc{sealcrypto,
        title = {{M}icrosoft {SEAL} (release 3.0)},
        howpublished = {\url{http://sealcrypto.org}},
        month = oct,
        year = 2018,
        note = {Microsoft Research, Redmond, WA.},
        key = {SEAL}
    }

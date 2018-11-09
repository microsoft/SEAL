# Introduction
SEAL (Simple Encrypted Arithmetic Library) is an easy-to-use homomorphic encryption 
library, developed by researchers in the Cryptography Research group at Microsoft 
Research. SEAL is written in standard C++17 and can be compiled also as C++14. 

# System requirements
Since SEAL has no external dependencies and is written in standard C++ it is easy 
to build on any 64-bit system. For building in Windows, SEAL contains a Visual 
Studio 2017 solution file. For building in Linux and Mac OS X, SEAL requires either 
g++-6 or newer, or clang++-5 or newer. Please see INSTALL.txt for installation 
instructions using CMake.

# Documentation
The code-base contains (see SEALExamples/main.cpp) extensive and thoroughly 
commented examples that should serve as a self-contained introduction to using SEAL.
In addition, the header files contain detailed comments for the public API.

# License
SEAL is licensed under the MIT license; see LICENSE.txt.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you 
to agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need 
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow 
the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) 
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional 
questions or comments.

# Acknowledgements
We would like to thank John Wernsing, Michael Naehrig, Nathan Dowlin, Rachel Player, 
Gizem Cetin, Susan Xia, Peter Rindal, Kyoohyung Han, Zhicong Huang, Amir Jalali, Wei Dai, 
Ilia Iliashenko, and Sadegh Riazi for their contributions to the SEAL project. We would also
like to thank everyone who has sent us helpful comments, suggestions, and bug reports.

# Contact Us
The best way to ask technical questions is on StackOverflow using the [seal] tag. To contact 
us directly, please email [sealcrypto@microsoft.com](mailto:sealcrypto@microsoft.com).

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_basic_ckks()
{
    print_example_banner("Example: Basic CKKS");

    /*
    In this example we demonstrate evaluating a polynomial function
    PI*x^3 + 0.4x + 1 on encrypted floating-point input data x for 4096
    equidistant points in the interval [0, 1]. The challenges we encounter will
    be related to matching scales and encryption parameters when adding together
    terms of different degrees in the polynomial evaluation.
    
    We start by setting up an environment similar to what we had in previously.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);

    /*
    Since the polynomial has degree 3, it has a multiplicative depth of 2.

    A multiplication in CKKS causes the scale of ciphertexts doubled. To ensure
    that the scale never exceeds the maximum coefficient modulus, we rescale
    the ciphertext to control or stablize the scale expansion. More precisely,
    suppose the scale in one level is S, the last coeff_modulus element is P,
    the scale after squaring and rescaling is 2S-P.

    For depth 2, we choose 4 primes...
    */
}
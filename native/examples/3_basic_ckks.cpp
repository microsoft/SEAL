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

    As shown in the example CKKS Encoder, a multiplication in CKKS causes the
    scale of ciphertexts doubled. The scale must not get too close to the total
    size of coeff_modulus. We can rescale the ciphertext to stablize the scale
    expansion. More precisely, suppose the scale before rescaling is S, the last
    prime in the current coeff_modulus vector is P, the scale after rescaling is
    2S-P.

    Naturally we would like to set the initial scale S and primes P_i in
    coeff_modulus involved in rescaling very close to each other, so that
    ciphertexts have scale S before multiplication, 2S after multiplication, and
    2S-P_i that approximately equals to S after rescaling. In this way, we
    stablize the scale in ciphertexts to be close to S. Generally for a circuit
    of depth D, we needs to rescale D times, i.e. removing D primes from
    coeff_modulus.

    Once we have only one prime left in coeff_modulus, the prime must be larger
    than S by a few bits to preserve the pre-decimal-point value of plaintexts.
    This prime is the first prime in coeff_modulus when we set up encryption
    parameters.

    The last prime in coeff_modulus used to set up encryption parameters is
    reserved for another purpose (to be explained in example Levels). It needs
    to be at least the same size of the largest other primes in coeff_modulus.

    For depth 2, we choose 4 primes: 1 larger prime for decryption, 2 smaller
    primes for rescaling, and 1 larger reserved prime). Microsoft SEAL provides
    a method that takes in a power-of-2 ring degee and the request number of
    primes, then returns an automatically generated vector of primes that suite
    this order. The sizes of primes in oeff_modulus have no effect on
    performance. It is advised to choose larger primes when you can.
    */
    /*
    By default, Microsoft SEAL chooses two 60-bit primes for both front and back of coeff_modulus.
    We choose two 40-bit primes in between for rescaling.
    */
    

}
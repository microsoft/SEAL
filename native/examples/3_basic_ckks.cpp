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
    PI*x^3 + 0.4*x + 1 on encrypted floating-point input data x for 4096
    equidistant points in the interval [0, 1]. The challenges we encounter will
    be related to matching scales and encryption parameters when adding together
    terms of different degrees in the polynomial evaluation.
    
    We start by setting up an environment similar to what we had in previously.
    */
    EncryptionParameters parms(scheme_type::CKKS);

    /*
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

    It is advised to choose larger primes for more noise budget (conceptually
    speaking).
    */

    /*
    The strategy to choose parameters is demonstrated below.
    
    We choose a 60-bit prime as the first element of coeff_modulus.
    This will give us the least risk of overflow at the decryption level.
    
    We choose another 60-bit prime as the last element of coeff_modulus.
    This almost eleminates the noise introduced by relinearization and rotation.

    Microsoft SEAL provides a method that generates a number of NTT-supportive
    prime numbers for a given bit size and NTT size.
    */
    vector<SmallModulus> primes = SmallModulus::GetPrimes(60, 2, 8192);

    /*
    We choose the initial scale to be 2.0^40. This gives us 20-bit precision
    before decimal point and enough (roughly 10-bit ~ 20-bit) precision after
    decimal point.
    */
    double scale = pow(2.0, 40);

    /* 
    We choose the rest primes for rescaling and stablizing scales. Since the
    polynomial has degree 3, it has a multiplicative depth of 2. Based on the
    number of multiplicative levels (2), we choose two primes. Based on the size
    of the initial scale, we choose each prime to be 40-bit. The sizes of primes
    have no effect on performance. The number of primes does.
    */
    vector<SmallModulus> primes_40 = SmallModulus::GetPrimes(40, 2, 8192);
    primes.insert(primes.begin() + 1, primes_40.begin(), primes_40.end());

    /*
    After all, we have 60 * 2 + 40 * 2 = 200 bits coefficient modulus. We choose
    polynomial_modulus_degree as 8192 for 128-bit security in the Security
    Standard Draft available at http://HomomorphicEncryption.org.

    If we choose a larger initial scale:
        - [Pro] More precision after decimal point.
        - [Con] Less precision before decimal point.
        - [Con] A larger polynomial_modulus_degree, e.g. 50-bit scale requires
                polynomial_modulus_degree = 16384.
    If we choose a smaller initial scale:
        - [Pro] More precisions before decimal point.
        - [Con] Less precisions after decimal point.
    */
    parms.set_coeff_modulus(primes);
    parms.set_poly_modulus_degree(8192);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintext elements for PI, 0.4, and 1, using an overload of
    CKKSEncoder::encode(...) that encodes the given floating-point value to
    every slot in the vector.
    */
    Plaintext plain_coeff3;
    encoder.encode(3.14159265, scale, plain_coeff3);
    Plaintext plain_coeff1;
    encoder.encode(0.4, scale, plain_coeff1);
    Plaintext plain_coeff0;
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext plain_x;
    cout << "-- Encoding input vector: ";
    encoder.encode(input, scale, plain_x);
    cout << "Done (plain x)" << endl;
    Ciphertext encrypted_x1;
    cout << "-- Encrypting input vector: ";
    encryptor.encrypt(plain_x, encrypted_x1);
    cout << "Done (encrypted x)" << endl;

    /*
    To compute x^3 we first compute x^2, relinearize, and rescale.
    */
    Ciphertext encrypted_x3;
    cout << "-- Computing x^2 and relinearizing: ";
    evaluator.square(encrypted_x1, encrypted_x3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    cout << "Done (x^2)" << endl;
    cout << "\tScale of x^2 before rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x3);
    cout << "\tScale of x^2  after rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;

    /*
    Now encrypted_x3 is at a different level (i.e. has different encryption
    parameters) than encrypted_x1, which prevents us from multiplying them
    together to compute x^3. We could simply switch encrypted_x1 down to the
    next parameters in the modulus switching chain.
    
    Since we still need to multiply the x^3 term with PI (plain_coeff3),
    we instead compute PI*x first and multiply that with x^2 to obtain PI*x^3.
    This product poses no problems since both inputs are at the same scale and
    use the same encryption parameters. We rescale afterwards to change the
    scale back to 40 bits, which will also drop the coefficient modulus down to
    120 bits.
    */
    cout << "-- Computing PI*x: ";
    Ciphertext encrypted_x1_coeff3;
    evaluator.multiply_plain(encrypted_x1, plain_coeff3, encrypted_x1_coeff3);
    cout << "Done (PI*x)" << endl;
    cout << "\tScale of PI*x before rescale: " << log2(encrypted_x1_coeff3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x1_coeff3);
    cout << "\tScale of PI*x  after rescale: " << log2(encrypted_x1_coeff3.scale())
        << " bits" << endl;

    /*
    Since encrypted_x3 and encrypted_x1_coeff3 have the same exact scale and use
    the same encryption parameters, we can multiply them together. We write the
    result to encrypted_x3.
    */
    cout << "-- Computing (PI*x)*x^2: ";
    evaluator.multiply_inplace(encrypted_x3, encrypted_x1_coeff3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    cout << "Done (PI*x^3)" << endl;
    cout << "\tScale of PI*x^3 before rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x3);
    cout << "\tScale of PI*x^3 after rescale: " << log2(encrypted_x3.scale())
        << " bits" << endl;

    /*
    Next we compute the degree one term. All this requires is one multiply_plain
    with plain_coeff1. We overwrite encrypted_x1 with the result.
    */
    cout << "-- Computing 0.4*x: ";
    evaluator.multiply_plain_inplace(encrypted_x1, plain_coeff1);
    cout << "Done (0.4*x)" << endl;
    cout << "\tScale of 0.4*x before rescale: " << log2(encrypted_x1.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(encrypted_x1);
    cout << "\tScale of 0.4*x after rescale: " << log2(encrypted_x1.scale())
        << " bits" << endl;

    /*
    Now we would hope to compute the sum of all three terms. However, there is
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.

    Homomorphic addition and subtraction naturally require that the scales of
    the inputs are the same, but also that the encryption parameters (parms_id)
    are the same. Note that a scale or parms_id mismatch would make
    Evaluator::add_plain(..) throw an exception.

    Another difference to the BFV scheme is that in CKKS also plaintexts are
    linked to specific parameter sets: they carry the corresponding parms_id.
    An overload of CKKSEncoder::encode(...) allows the caller to specify which
    parameter set in the modulus switching chain (identified by parms_id) should
    be used to encode the plaintext. This is important as we will see later.
    */
    cout << endl << "Parameters used by all three terms are different:" << endl;
    cout << "\tModulus chain index for encrypted_x3: "
        << context->get_context_data(encrypted_x3.parms_id())->chain_index() << endl;
    cout << "\tModulus chain index for encrypted_x1: "
        << context->get_context_data(encrypted_x1.parms_id())->chain_index() << endl;
    cout << "\tModulus chain index for plain_coeff0: "
        << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. We denote the
    primes in coeff_modulus as q0, q1, q2, q3 (order matters here). q3 is not
    used in rescaling. All fresh encodings start with a scale equal to 2.0^80.
    After the computations above the scales in ciphertexts are:

          - Product x^2 has scale 2.0^80;
          - Product PI*x has scale 2.0^80;
          - Rescaling both of these by q2 results in scale 2.0^80/q2;
          - Product PI*x^3 has scale (2.0^80/q2)^2;
        - Rescaling by q1 results in scale (2.0^80/q2)^2/q1;
          - Product 0.4*x has scale 2.0^80;
        - Rescaling q2 results in scale 2.0^80/q2;
        - The contant term 1 has 2.0^40;

    Although the scales of all three terms are approximately 2.0^40, their exact
    values are different.
    */
    cout << endl << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "\tExact scale in PI*x^3: " << encrypted_x3.scale() << endl;
    cout << "\tExact scale in 0.4*x: " << encrypted_x1.scale() << endl;
    cout << "\tExact scale in 1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are many ways to fix this problem about scales. Since q2 and q1 are
    really close to 2.0^40, we can simply "lie" to Microsoft SEAL and set the
    scales to be the same. For example, changing the scale of PI*x^3 to 2.0^40
    simply means that we scale the value of PI*x^3 by 2.0^120/q2/q2/q1 which is
    very close to 1. This should not result in any noticeable error.

    Another option would be to encode 1 with scale 2.0^80/q2, perform a
    multiply_plain with 0.4*x, and finally rescale. In this case we would
    additionally make sure to encode 1 with appropriate encryption parameters
    (parms_id).

    In this example we will use the first (simplest) approach and simply change
    the scale of PI*x^3 and 0.4*x to 2.0^40.
    */
    cout << "-- Matching scales: ";
    encrypted_x3.scale() = plain_coeff0.scale();
    encrypted_x1.scale() = plain_coeff0.scale();
    cout << "Done (2.0^40)" << endl;

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). CKKS supports
    modulus switching just like the BFV scheme. We can switch away parts of the
    coefficient modulus. Note that we use here the
    Evaluator::mod_switch_to_inplace(...) function to switch to encryption
    parameters down the chain with a specific parms_id.
    */
    cout << "-- Matching parms_id: ";
    evaluator.mod_switch_to_inplace(encrypted_x1, encrypted_x3.parms_id());
    evaluator.mod_switch_to_inplace(plain_coeff0, encrypted_x3.parms_id());
    cout << "Done" << endl;

    /*
    All three ciphertexts are now compatible and can be added.
    */
    cout << "-- Computing PI*x^3 + 0.4*x + 1: ";
    Ciphertext encrypted_result;
    evaluator.add(encrypted_x3, encrypted_x1, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);
    cout << "Done (PI*x^3 + 0.4*x + 1)" << endl;

    /*
    We decrypt, decode, and print the result.
    */
    Plaintext plain_result;
    cout << "-- Decrypting and decoding: ";
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Done" << endl;
    
    cout << endl;
    cout << "Computed result of PI*x^3 + 0.4x + 1:" << endl;
    print_vector(result, 3, 7);

    cout << "Expected result of PI*x^3 + 0.4x + 1:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4)* x + 1);
    }
    print_vector(true_result, 3, 7);

    /*
    We can also rotate an encrypted vector (see example_rotation_ckks).

    We did not show any computations on complex numbers in these examples, but
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications behave just as one would expect. It is also possible
    to complex conjugate the values in a ciphertext by using the functions
    Evaluator::complex_conjugate[_inplace](...).
    */
}
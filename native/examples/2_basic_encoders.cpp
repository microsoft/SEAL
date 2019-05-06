// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_integer_encoder()
{
    print_example_banner("Integer Encoder");

    /*
    [IntegerEncoder] (BFV specific)

    The IntegerEncoder encodes integers to BFV plaintext polynomials as follows.
    First, a binary expansion of the integer is computed. Next, a polynomial is
    created with the bits as coefficients. For example, the integer

        26 = 2^4 + 2^3 + 2^1

    is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. Conversely, plaintext
    polynomials are decoded by evaluating them at x=2. For negative numbers the
    IntegerEncoder simply stores all coefficients as either 0 or -1, where -1 is
    represented by the unsigned integer plain_modulus - 1 in memory.

    Since encrypted computations operate on the polynomials rather than on the
    encoded integers themselves, the polynomial coefficients will grow in the
    course of such computations. For example, computing the sum of the encrypted
    encoded integer 26 with itself will result in an encrypted polynomial with
    larger coefficients: 2x^4 + 2x^3 + 2x^1. Squaring the encrypted encoded
    integer 26 results also in increased coefficients due to cross-terms, namely,

        (1x^4 + 1x^3 + 1x^1)^2 = 1x^8 + 2x^7 + 1x^6 + 2x^5 + 2x^4 + 1x^2;

    further computations will quickly increase the coefficients much more.
    Decoding will still work correctly in this case (evaluating the polynomial
    at x=2), but since the coefficients of plaintext polynomials are really
    integers modulo plain_modulus, implicit reduction modulo plain_modulus may
    yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself
    plain_modulus many times will result in the constant polynomial 0, which is
    clearly not equal to 26 * plain_modulus. It can be difficult to predict when
    such overflow will take place especially when computing several sequential
    multiplications.

    The IntegerEncoder is easy to understand and use for simple computations,
    and can be a good starting point to learning Microsoft SEAL. However,
    advanced users will probably prefer more efficient approaches, such as the
    BatchEncoder or the CKKSEncoder.
    */
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
    parms.set_plain_modulus(512);
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    We create the IntegerEncoder.
    */
    IntegerEncoder encoder(context);

    /*
    First, encode two integers as plaintext polynomials. Note that encoding is
    not encryption: at this point nothing is encrypted.
    */
    int value1 = 5;
    Plaintext plain1 = encoder.encode(value1);
    cout << "-- Encoded " << value1 << " as polynomial " << plain1.to_string()
        << " (plain1)" << endl;

    int value2 = -7;
    Plaintext plain2 = encoder.encode(value2);
    cout << "-- Encoded " << value2 << " as polynomial " << plain2.to_string()
        << " (plain2)" << endl;

    /*
    Now we can encrypt the plaintext polynomials.
    */
    Ciphertext encrypted1, encrypted2;
    cout << "-- Encrypting plain1: ";
    encryptor.encrypt(plain1, encrypted1);
    cout << "Done (encrypted1)" << endl;
    cout << "\tNoise budget in encrypted1: "
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    cout << "-- Encrypting plain2: ";
    encryptor.encrypt(plain2, encrypted2);
    cout << "Done (encrypted2)" << endl;
    cout << "\tNoise budget in encrypted2: "
        << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;

    /*
    As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2.
    */
    cout << "-- Computing (-encrypted1 + encrypted2) * encrypted2: ";
    evaluator.negate_inplace(encrypted1);
    evaluator.add_inplace(encrypted1, encrypted2);
    evaluator.multiply_inplace(encrypted1, encrypted2);
    cout << "Done" << endl;
    cout << "\tNoise budget in (-encrypted1 + encrypted2) * encrypted2: "
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
    Plaintext plain_result;
    cout << "-- Decrypting result: ";
    decryptor.decrypt(encrypted1, plain_result);
    cout << "Done" << endl;

    /*
    Print the result plaintext polynomial.
    */
    cout << "\tPlaintext polynomial: " << plain_result.to_string() << endl;

    /*
    Decode to obtain an integer result.
    */
    cout << "\tDecoded integer: " << encoder.decode_int32(plain_result) << endl;
}

void example_batch_encoder()
{
    print_example_banner("Batch Encoder");

    /*
    [BatchEncoder] (BFV specific)

    If N denotes the degree of the polynomial modulus, and T the plaintext
    modulus, then batching is automatically enabled for the BFV scheme when T
    is a prime number congruent to 1 modulo 2*N.

    Batching allows the BFV plaintext polynomial to be viewed as a 2-by-(N/2)
    matrix, with each element an integer modulo T. In the matrix view, homomorphic
    operations act element-wise on encrypted matrices, allowing the user to obtain
    speeds-ups of several orders of magnitude in fully vectorizable computations.
    Thus, in all but the simplest computations, batching should be the preferred
    method to use, and when used properly will result in implementations that far
    outperform anything done with the IntegerEncoder.
    */
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    /*
    Note that 40961 is a prime number and 2*4096 divides 40960, so batching will
    automatically be enabled for these parameters.
    */
    parms.set_plain_modulus(65537);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    */
    auto qualifiers = context->first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching is done through an instance of the BatchEncoder class.
    */
    BatchEncoder batch_encoder(context);

    /*
    The total number of batching `slots' equals the degree of the polynomial
    modulus. The matrices we encrypt will be of size 2-by-(slot_count / 2).
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers. The first `row_size' many numbers form the first row, and the
    rest form the second row. Here we create the following matrix:

        [ 0,  1,  2,  3,  0,  0, ...,  0 ]
        [ 4,  5,  6,  7,  0,  0, ...,  0 ]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << endl;
    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    */
    Plaintext plain_matrix;
    cout << "-- Encoding plaintext matrix: ";
    batch_encoder.encode(pod_matrix, plain_matrix);
    cout << "Done" <<endl;

    /*
    We can instantly decode to verify correctness of the encoding.
    */
    vector<uint64_t> pod_result;
    cout << "   Decoding plaintext matrix: ";
    batch_encoder.decode(plain_matrix, pod_result);
    cout << " Done." <<endl;
    cout << "\tPlaintext matrix:" << endl;
    print_matrix(pod_result, row_size);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext encrypted_matrix;
    cout << "-- Encrypting: ";
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Done" << endl;
    cout << "\tNoise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 4096 slots (matrix elements). To illustrate this, we
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and encode it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i % 2) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /*
    We now add the second (plaintext) matrix to the encrypted matrix, and square
    the sum.
    */
    cout << "-- Adding and squaring: ";
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);
    cout << "Done" << endl;

    /*
    How much noise budget do we have left?
    */
    cout << "\tNoise budget in result: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    We decrypt and decompose the plaintext to recover the result as a matrix.
    */
    Plaintext plain_result;
    cout << "-- Decrypting result: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    cout << "Done" << endl;

    cout << "-- Decoding result: ";
    batch_encoder.decode(plain_result, pod_result);
    cout << "Done" << endl;
    cout << "\tResult plaintext matrix:" << endl;
    print_matrix(pod_result, row_size);
}

void example_ckks_encoder()
{
    print_example_banner("CKKS Encoder");

    /*
    In this example we demonstrate the encoder for the Cheon-Kim-Kim-Song (CKKS)
    scheme for encrypting and computing on floating point numbers. For full
    details on the CKKS scheme, we refer to https://eprint.iacr.org/2016/421.
    For better performance, Microsoft SEAL implements the "FullRNS" optimization
    for CKKS, as described in https://eprint.iacr.org/2018/931.
    */

    /*
    We start by creating encryption parameters for the CKKS scheme. One major
    difference to the BFV scheme is that CKKS does not use the plain_modulus.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    /*
    We create the SEALContext as usual and print the parameters.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    Keys are created the same way as for the BFV scheme.
    */
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();

    /*
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    To create CKKS plaintexts we need a special encoder: we cannot create them
    directly from polynomials. Note that the IntegerEncoder and BatchEncoder
    cannot be used with the CKKS scheme. The CKKS scheme allows encryption and
    approximate computation on vectors of real or complex numbers, which the
    CKKSEncoder converts into Plaintext objects. At a high level this looks a lot
    like BatchEncoder for the BFV scheme, but the theory behind it is different.
    */
    CKKSEncoder encoder(context);

    /*
    In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
    one complex (or real) number. This should be contrasted with BatchEncoder in
    the BFV scheme, where the number of slots is equal to poly_modulus_degree
    and they are arranged into a 2-by-(poly_modulus_degree / 2) matrix.
    */
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    We create a small vector to encode; the CKKSEncoder will implicitly pad it
    with zeros to full size (poly_modulus_degree / 2) when encoding.
    */
    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << endl;
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
    will be scaled up by the parameter `scale'; this is necessary since even in
    the CKKS scheme the plaintexts are polynomials with integer coefficients. It
    is instructive to think of the scale as determining the bit-precision of the
    encoding; naturally it will also affect the precision of the result.

    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
    plain_modulus), so the scale must not get too close to the total size of
    coeff_modulus. In this case our coeff_modulus is quite large (218 bits) so we
    have little to worry about in this regard. For this example a 50-bit scale is
    more than enough.
    */
    Plaintext plain;
    double scale = pow(2.0, 50);
    cout << "-- Encoding input vector: ";
    encoder.encode(input, scale, plain);
    cout << "Done" << endl;

    /*
    We can instantly decode to check the correctness of encoding.
    */
    vector<double> output;
    cout << "   Decoding input vector: ";
    encoder.decode(plain, output);
    cout << "Done" << endl;
    cout << "\tDecoded input vector: " << endl;
    print_vector(input);

    /*
    The vector is encrypted the same was as in BFV.
    */
    Ciphertext encrypted;
    cout << "-- Encrypting input vector: ";
    encryptor.encrypt(plain, encrypted);
    cout << "Done" << endl;

    /*
    Basic operations on the ciphertexts are still easy to do. Here we square
    the ciphertext, decrypt, decode, and print the result. We note also that
    decoding returns a vector of full size (poly_modulus_degree / 2); this is
    because of the implicit zero-padding mentioned above.
    */
    cout << "-- Squaring: ";
    evaluator.square_inplace(encrypted);
    cout << "Done" << endl;
    cout << "-- Relinearizing: ";
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Done" << endl;

    /*
    We notice that the scale in the result has increased. In fact, it is now the
    square of the original scale (2^50).
    */
    cout << "\tScale in squared input: " << encrypted.scale()
        << " (" << log2(encrypted.scale()) << " bits)" << endl;

    cout << "-- Decrypting: ";
    decryptor.decrypt(encrypted, plain);
    cout << "Done" << endl;
    cout << "-- Decoding: ";
    encoder.decode(plain, output);
    cout << "Done" << endl;
    cout << "\tSquared input: " << endl;
    print_vector(output);
}

void example_basic_encoders()
{
  print_example_banner("Example: Basic Encoders");

  example_integer_encoder();

  example_batch_encoder();

  example_ckks_encoder();
}
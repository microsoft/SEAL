// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    /*
    In this example, we demonstrate performing simple computations (a polynomial
    evaluation) on encrypted integers. Microsoft SEAL implements two encryption
    schemes:

        (1) Brakerski/Fan-Vercauteren (BFV) scheme;
        (2) Cheon-Kim-Kim-Song (CKKS) scheme.

    We use the BFV scheme in this example as it is far easier to understand and
    to use than CKKS. For more details on the basics of the BFV scheme, we refer
    the reader to the original paper https://eprint.iacr.org/2012/144. To achieve
    good performance, Microsoft SEAL implements the "FullRNS" optimization as
    described in https://eprint.iacr.org/2016/510. This optimization is invisible
    to the user and has no security implications. We will discuss the CKKS scheme
    in later examples.

    The first task is to set up an instance of the EncryptionParameters class.
    It is critical to understand how the different parameters behave, how they
    affect the encryption scheme, performance, and the security level. There are
    three encryption parameters that are necessary to set:

        - poly_modulus_degree (degree of polynomial modulus);
        - coeff_modulus ([ciphertext] coefficient modulus);
        - plain_modulus (plaintext modulus, only for the BFV scheme).

    A fourth parameter -- noise_standard_deviation -- has a default value 3.20
    and should not be necessary to modify unless the user has a specific reason
    to do so and has an in-depth understanding of the security implications.

    A fifth parameter -- random_generator -- can be set to use customized random
    number generators. By default, Microsoft SEAL uses hardware-based AES in
    counter mode for pseudo-randomness, with a random key generated using
    std::random_device. If the AES-NI instruction set is not available, all
    randomness is generated from std::random_device. Most users should have
    little reason to change this behavior.

    The BFV scheme cannot perform arbitrary computations on encrypted data.
    Instead, each ciphertext has a specific quantity called the `invariant noise
    budget' -- or `noise budget' for short -- measured in bits. The noise budget
    in a freshly encrypted ciphertext (initial noise budget) is determined by
    the encryption parameters. Homomorphic operations consume the noise budget
    at a rate also determined by the encryption parameters. In BFV the two basic
    operations allowed on encrypted data are additions and multiplications, of
    which additions can generally be thought of as being nearly free in terms of
    noise budget consumption compared to multiplications. Since noise budget
    consumption compounds in sequential multiplications, the most significant
    factor in choosing appropriate encryption parameters is the multiplicative
    depth of the arithmetic circuit that the user wants to evaluate on encrypted
    data. Once the noise budget of a ciphertext reaches zero it becomes too
    corrupted to be decrypted. Thus, it is essential to choose the parameters to
    be large enough to support the desired computation; otherwise the result is
    impossible to make sense of even with the secret key.
    */
    EncryptionParameters parms(scheme_type::BFV);

    /*
    The first parameter we set is the degree of the `polynomial modulus'. This
    must be a positive power of 2, representing the degree of a power-of-two
    cyclotomic polynomial; it is not necessary to understand what this means.

    Larger poly_modulus_degree makes ciphertext sizes larger and all operations
    slower, but enables more complicated encrypted computations. Recommended
    values are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible
    to go beyond this range. 
    
    In this example we use a relatively small polynomial modulus;
    anything smaller than this will enable only extremely restricted encrypted
    computations.
    */
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    Next we set the [ciphertext] `coefficient modulus' (coeff_modulus). This
    parameter is a large integer, which is a product of distinct prime numbers,
    each up to 60 bits in size. It is represented as a vector of these prime
    numbers, each represented by an instance of the SmallModulus class.

    A larger coeff_modulus implies a larger noise budget, hence more encrypted
    computation capabilities. However, an upper bound for the total bit-length
    of the coeff_modulus is determined by the poly_modulus_degree, as follows:

        poly_modulus_degree | max coeff_modulus bit-length
        --------------------------------------------------------
        1024                | 27
        2048                | 54
        4096                | 109
        8192                | 218
        16384               | 438
        32768               | 881

    These numbers can also be found in native/src/seal/util/hestdparms.h encoded
    in the function SEAL_HE_STD_PARMS_128_TC, and can also be obtained from the
    function 
        
        CoeffModulus::MaxBitCount(poly_modulus_degree).
    
    For example, if poly_modulus_degree is 4096, the coeff_modulus could consist
    of three 36-bit primes (108 bits).

    Microsoft SEAL comes with helper functions for selecting the coeff_modulus.
    For new users the easiest way is to simply use
        
        CoeffModulus::Default(poly_modulus_degree),

    which returns std::vector<SmallModulus> consisting of a generally good choice
    for the given poly_modulus_degree. In later examples we will use the function

        CoeffModulus::Custom(poly_modulus_degree, { ... })

    to obtain customized primes for the coeff_modulus, and will explain reasons
    for doing so.
    */
    parms.set_coeff_modulus(CoeffModulus::Default(poly_modulus_degree));

    /*
    The plaintext modulus can be any positive integer, even though here we take
    it to be a power of two. In fact, in many cases one might instead want it
    to be a prime number; we will see this in later examples. The plaintext
    modulus determines the size of the plaintext data type and the consumption
    of noise budget in multiplications. Thus, it is essential to try to keep the
    plaintext data type as small as possible for best performance. The noise
    budget in a freshly encrypted ciphertext is

        ~ log2(coeff_modulus/plain_modulus) (bits)

    and the noise budget consumption in a homomorphic multiplication is of the
    form log2(plain_modulus) + (other terms).
    
    The plaintext modulus is specific to the BFV scheme, and cannot be set when
    using the CKKS scheme.
    */
    parms.set_plain_modulus(256);

    /*
    Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set and performs several important pre-computations.
    */
    auto context = SEALContext::Create(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_parameters(context);

    /*
    The encryption schemes in Microsoft SEAL are public key encryption schemes.
    For users unfamiliar with this terminology, a public key encryption scheme
    has a separate public key for encrypting data, and a separate secret key for
    decrypting data. This way multiple parties can encrypt data using the same
    shared public key, but only the proper recipient of the data can decrypt it
    with the secret key.

    We are now ready to generate the secret and public keys. For this purpose
    we need an instance of the KeyGenerator class. Constructing a KeyGenerator
    automatically generates the public and secret key, which can immediately be
    read to local variables.
    */
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    /*
    To be able to encrypt we need to construct an instance of Encryptor. Note
    that the Encryptor only requires the public key, as expected.
    */
    Encryptor encryptor(context, public_key);

    /*
    Computations on the ciphertexts are performed with the Evaluator class. In
    a real use-case the Evaluator would not be constructed by the same party
    that holds the secret key.
    */
    Evaluator evaluator(context);

    /*
    We will of course want to decrypt our results to verify that everything worked,
    so we need to also construct an instance of Decryptor. Note that the Decryptor
    requires the secret key.
    */
    Decryptor decryptor(context, secret_key);

    /*
    As an example, we evaluate the degree 4 polynomial

        2x^4 + 4x^3 + 4x^2 + 4x + 2

    over an encrypted x = 6. The coefficients of the polynomial can be considered
    as plaintext inputs, as we will see below. The computation is done modulo the
    plain_modulus 256.

    While this examples is simple and easy to understand, it does not have much
    practical value. In later examples we will demonstrate how to compute more
    efficiently on encrypted integers and real or complex numbers.

    Plaintexts in the BFV scheme are polynomials of degree less than the degree
    of the polynomial modulus, and coefficients integers modulo the plaintext
    modulus. For readers with background in ring theory, the plaintext space is
    the polynomial quotient ring Z_T[X]/(X^N + 1), where N is poly_modulus_degree
    and T is plain_modulus.

    To get started, we create a plaintext containing the constant 6. For the
    plaintext element we use a constructor that takes the desired polynomial as
    a string with coefficients represented as hexadecimal numbers.
    */
    int x = 6;
    Plaintext plain_x(to_string(x));

    cout << "-- Express x = " << x << " as a plaintext polynomial 0x"
        << plain_x.to_string() << endl;

    /*
    We then encrypt the plaintext, producing a ciphertext.
    */
    Ciphertext encrypted_x;
    cout << "-- Encrypting plain_x: ";
    encryptor.encrypt(plain_x, encrypted_x);
    cout << "Done (encrypted_x)" << endl;

    /*
    In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
    whose coefficients are integers modulo the product of the primes in the
    coeff_modulus. The number of polynomials in a ciphertext is called its `size'
    and is given by Ciphertext::size(). A freshly encrypted ciphertext always
    has size 2.
    */
    cout << "\tSize of freshly encrypted x: " << encrypted_x.size() << endl;

    /*
    There is plenty of noise budget left in this freshly encrypted ciphertext.
    */
    cout << "\tNoise budget in freshly encrypted x: "
        << decryptor.invariant_noise_budget(encrypted_x) << " bits" << endl;

    /*
    We decrypt the ciphertext and print the resulting plaintext in order to
    demonstrate correctness of the encryption.
    */
    Plaintext decrypted_x;
    cout << "   Decrypting encrypted_x: ";
    decryptor.decrypt(encrypted_x, decrypted_x);
    cout << "Done (decrypted_x = 0x" << decrypted_x.to_string() << ")" << endl;

    /*
    When using Microsoft SEAL, it is typically advantageous to compute in a way
    that minimizes the longest chain of sequential multiplications. In other
    words, encrypted computations are best evaluated in a way that minimizes
    the multiplicative depth of the computation, because the total noise budget
    consumption is proportional to the multiplicative depth. For example, for
    our example computation it is advantageous to factorize the polynomial as

        2x^4 + 4x^3 + 4x^2 + 4x + 2 = 2(x + 1)^2 * (x^2 + 1)

    to obtain a simple depth 2 representation. Thus, we compute (x + 1)^2 and
    (x^2 + 1) separately, before multiplying them, and multiplying by 2.

    First, we compute x^2 and add a plaintext "1". We can clearly see from the
    print-out that multiplication has consumed a lot of noise budget. The user
    can vary the plain_modulus parameter to see its effect on the rate of noise
    budget consumption.
    */
    cout << "-- Computing x^2+1: ";
    Ciphertext x_squared_plus_one;
    evaluator.square(encrypted_x, x_squared_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_squared_plus_one, plain_one);
    cout << "Done" << endl;

    /*
    Encrypted multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform a squaring, and observe both size growth and noise budget
    consumption.
    */
    cout << "\tSize of x^2+1: " << x_squared_plus_one.size() << endl;
    cout << "\tNoise budget in x^2+1: "
        << decryptor.invariant_noise_budget(x_squared_plus_one) << " bits" << endl;

    /*
    It does not matter that the size has grown -- decryption works as usual, as
    long as noise budget has not reached 0.
    */
    Plaintext decrypted_result;
    cout << "   Decrypting x^2+1: ";
    decryptor.decrypt(x_squared_plus_one, decrypted_result);
    cout << "Done (x^2+1 = 0x" << decrypted_result.to_string() << ")" << endl;

    /*
    Next, we compute (x + 1)^2.
    */
    cout << "-- Computing (x+1)^2: ";
    Ciphertext x_plus_one_squared;
    evaluator.add_plain(encrypted_x, plain_one, x_plus_one_squared);
    evaluator.square_inplace(x_plus_one_squared);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2: " << x_plus_one_squared.size() << endl;
    cout << "\tNoise budget in (x+1)^2: "
        << decryptor.invariant_noise_budget(x_plus_one_squared)
        << " bits" << endl;
    cout << "   Decrypting (x+1)^2: ";
    decryptor.decrypt(x_plus_one_squared, decrypted_result);
    cout << "Done ((x+1)^2 = 0x" << decrypted_result.to_string() << ")" << endl;

    /*
    Finally, we multiply (x^2 + 1) * (x + 1)^2 * 2.
    */
    cout << "-- Computing 2(x^2+1)(x+1)^2: ";
    Ciphertext encrypted_result;
    evaluator.multiply(x_squared_plus_one, x_plus_one_squared, encrypted_result);
    Plaintext plain_two("2");
    evaluator.multiply_plain_inplace(encrypted_result, plain_two);
    cout << "Done" << endl;
    cout << "\tSize of 2(x^2+1)(x+1)^2: " << encrypted_result.size() << endl;
    cout << "\tNoise budget in 2(x^2+1)(x+1)^2: "
        << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
    cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;
    cout << endl;

    /*
    Noise budget has reached 0, which means that decryption cannot be expected to
    give the correct result. This is because both ciphertexts x_squared_plus_one
    and x_plus_one_squared consist of 3 polynomials due to the previous squaring
    operations, and homomorphic operations on large ciphertexts consume much more
    noise budget than computations on small ciphertexts. Computing on smaller
    ciphertexts is also computationally significantly cheaper.

    `Relinearization' is an operation that reduces the size of a ciphertext after
    multiplication back to the initial size, 2. Thus, relinearizing one or both
    input ciphertexts before the next multiplication can have a huge positive
    impact on both noise growth and performance, even though relinearization has
    a significant computational cost itself.

    Relinearization requires a special `relinearization key', which can be thought
    of as a kind of public key. Relinerization keys can easily be created with the
    KeyGenerator. To relinearize a ciphertext of size M >= 2 back to size 2, we
    actually need M-2 relinearization keys. Attempting to relinearize a too large
    ciphertext with too few relinearization keys will result in an exception being
    thrown. It is common to relinearize after every multiplication, in which case
    ciphertexts never reach size bigger than 3, and only a single relinearization
    key is needed.

    Relinearization is used similarly in both the BFV and the CKKS schemes, but
    in this example we continue using BFV. We repeat our computation from before,
    but this time relinearize after every multiplication.

    We use KeyGenerator::relin_keys() to create a single relinearization key.
    This function accepts optionally the number of relinearization keys to be
    generated.
    */
    cout << "-- Generating relinearization keys: ";
    auto relin_keys = keygen.relin_keys();
    cout << "Done" << endl;

    /*
    We now repeat the computation relinearizing after each multiplication.
    */
    cout << "-- Computing x^2: ";
    evaluator.square(encrypted_x, x_squared_plus_one);
    cout << "Done" << endl;
    cout << "\tSize of x^2: " << x_squared_plus_one.size() << endl;
    cout << "-- Relinearizing x^2: ";
    evaluator.relinearize_inplace(x_squared_plus_one, relin_keys);
    cout << "Done" << endl;
    cout << "\tSize of x^2 (after relinearization): "
        << x_squared_plus_one.size() << endl;
    cout << "-- Computing x^2+1: ";
    evaluator.add_plain_inplace(x_squared_plus_one, plain_one);
    cout << "Done" << endl;
    cout << "\tNoise budget in x^2+1: "
        << decryptor.invariant_noise_budget(x_squared_plus_one) << " bits" << endl;

    cout << "-- Computing x+1: ";
    evaluator.add_plain(encrypted_x, plain_one, x_plus_one_squared);
    cout << "Done" << endl;
    cout << "-- Computing (x+1)^2: ";
    evaluator.square_inplace(x_plus_one_squared);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2: " << x_plus_one_squared.size() << endl;
    cout << "-- Relinearizing (x+1)^2: ";
    evaluator.relinearize_inplace(x_plus_one_squared, relin_keys);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2 (after relinearization): "
        << x_plus_one_squared.size() << endl;
    cout << "\tNoise budget in (x+1)^2: "
        << decryptor.invariant_noise_budget(x_plus_one_squared) << " bits" << endl;

    cout << "-- Computing (x^2+1)(x+1)^2: ";
    evaluator.multiply(x_squared_plus_one, x_plus_one_squared, encrypted_result);
    cout << "Done" << endl;
    cout << "\tSize of (x^2+1)(x+1)^2: " << encrypted_result.size() << endl;
    cout << "-- Relinearizing (x^2+1)(x+1)^2: ";
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "Done" << endl;
    cout << "\tSize of (x^2+1)(x+1)^2 (after relinearization): "
        << encrypted_result.size() << endl;
    cout << "-- Computing 2(x^2+1)(x+1)^2: ";
    evaluator.multiply_plain_inplace(encrypted_result, plain_two);
    cout << "Done" << endl;
    cout << "\tNoise budget in 2(x^2+1)(x+1)^2: "
        << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
    cout << "NOTE: Notice the increase in remaining noise budget." << endl;

    /*
    Relinearization clearly improved our noise consumption. We clearly have noise
    budget left, so we can expect the correct answer when decrypting.
    */
    cout << "-- Decrypting 2(x^2+1)(x+1)^2: ";
    decryptor.decrypt(encrypted_result, decrypted_result);
    cout << "Done (2(x^2+1)(x+1)^2 = 0x" << decrypted_result.to_string() << ")" << endl;
    cout << endl;

    /*
    For x=6, 2(x^2+1)(x+1)^2 = 3626. Since the plaintext modulus is set to 256,
    this result is computed in integers modulo 256. Therefore the expected output
    should be 3626 % 256 == 42, or 0x2A in hexadecimal.
    */
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_basic_bfv()
{
    print_example_banner("Example: Basic BFV");

    /*
    In this example, we demonstrate performing simple computations (a polynomial
    evaluation) on encrypted integers.

    Microsoft SEAL implements two encryption schemes:
        - the Brakerski/Fan-Vercauteren (BFV) scheme and
        - the Cheon-Kim-Kim-Song (CKKS) scheme.
    We use the BFV scheme in this example as it is far easier to understand and
    to use than CKKS. The public interface of BFV and CKKS differ very little
    in Microsoft SEAL. For more details on the basics of the BFV scheme, we
    refer the reader to the original paper https://eprint.iacr.org/2012/144.
    To achieve good performance, Microsoft SEAL implements the "FullRNS"
    optimization as described in https://eprint.iacr.org/2016/510. This
    optimization is invisible to the user and has no security implications. We
    will discuss the CKKS scheme in later examples.
    */

    /*
    The first task is to set up an instance of the EncryptionParameters class.
    It is critical to understand how these different parameters behave, how they
    affect the encryption scheme, performance, and the security level. There are
    three encryption parameters that are necessary to set:

        - poly_modulus_degree (degree of polynomial modulus);
        - coeff_modulus ([ciphertext] coefficient modulus);
        - plain_modulus (plaintext modulus, BFV-specific).

    A fourth parameter -- noise_standard_deviation -- has a default value 3.20
    and should not be necessary to modify unless the user has a specific reason
    to do so and has an in-depth understanding of the security implications.

    A fifth parameter -- random_generator -- can be set to use customized random
    number generators. By default, Microsoft SEAL uses hardware-based AES in
    counter mode for pseudo-randomness with key generated using
    std::random_device. If the AES-NI instruction set is not available, all
    randomness is generated from std::random_device. Most academic users in
    particular should have little reason to change this.

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
    The first parameter we set is the degree of the polynomial modulus. This must
    be a positive power of 2, representing the degree of a power-of-2 cyclotomic
    polynomial; it is not necessary to understand what this means. The polynomial
    modulus degree should be thought of mainly affecting the security level of the
    scheme: larger degree makes the scheme more secure. Larger degree also makes
    ciphertext sizes larger, and consequently all operations slower. Recommended
    degrees are 1024, 2048, 4096, 8192, 16384, 32768, but it is also possible to
    go beyond this. In this example we use a relatively small polynomial modulus.
    */
    parms.set_poly_modulus_degree(4096);

    /*
    Next we set the [ciphertext] coefficient modulus (coeff_modulus). The size
    of the coefficient modulus should be thought of as the most significant
    factor in determining the noise budget in a freshly encrypted ciphertext:
    bigger means more noise budget, which is desirable. On the other hand,
    a larger coefficient modulus lowers the security level of the scheme. Thus,
    if a large noise budget is required for complicated computations, a large
    coefficient modulus needs to be used, and the reduction in the security
    level must be countered by simultaneously increasing the polynomial modulus.
    Overall, this will result in worse performance.

    To make parameter selection easier for the user, we have constructed sets
    of the largest safe coefficient moduli for 128-bit and 192-bit security levels
    for different choices of the polynomial modulus. These default parameters
    follow the recommendations in the Security Standard Draft available at
    http://HomomorphicEncryption.org. The security estimates are a complicated
    topic and we highly recommend consulting with experts in the field when
    selecting parameters.

    Our recommended values for the coefficient modulus can be easily accessed
    through the functions

        DefaultParams::coeff_modulus_128(int poly_modulus_degree)
        DefaultParams::coeff_modulus_192(int poly_modulus_degree)
        DefaultParams::coeff_modulus_256(int poly_modulus_degree)

    for 128-bit, 192-bit, and 256-bit security levels. The integer parameter is
    the degree of the polynomial modulus used.

    In Microsoft SEAL the coefficient modulus is a positive composite number --
    a product of distinct primes of size up to 60 bits. When we talk about the size
    of the coefficient modulus we mean the bit length of the product of the primes.
    The small primes are represented by instances of the SmallModulus class so for
    example DefaultParams::coeff_modulus_128(int) returns a vector of SmallModulus
    instances.

    It is possible for the user to select their own small primes. Since Microsoft
    SEAL uses the Number Theoretic Transform (NTT) for polynomial multiplications
    modulo the factors of the coefficient modulus, the factors need to be prime
    numbers congruent to 1 modulo 2*poly_modulus_degree. We have generated a list
    of such prime numbers of various sizes that the user can easily access through
    the functions

        DefaultParams::small_mods_60bit(int poly_modulus_degree)
        DefaultParams::small_mods_50bit(int poly_modulus_degree)
        DefaultParams::small_mods_40bit(int poly_modulus_degree)
        DefaultParams::small_mods_30bit(int poly_modulus_degree)

    each of which gives access to an array of primes of the denoted size. These
    primes are located in the source file util/globals.cpp. Again, please keep
    in mind that the choice of coeff_modulus has a dramatic effect on security
    and should almost always be obtained through coeff_modulus_xxx(int).

    For more a flexible prime selection, we have added a prime generation method

        SmallModulus::GetPrimes(
            std::size_t bit_size, std::size_t count, std::size_t ntt_size)

    that returns the largest "count" primes with "bit_size" bits which support
    NTT of size "ntt_size".

    Performance is mainly affected by the size of the polynomial modulus, and
    the number of prime factors in the coefficient modulus; hence in some cases
    it can be important to use as few prime factors in the coefficient modulus
    as possible.

    However, there are scenarios that are demonstrated in later examples where
    a user would like to choose more small primes than the default parameters.
    We provide a method
    \todo Make sure this is the correct API.
        DefaultParams::coeff_modulus_128(int poly_modulus_degree,
                                        std::size_t coeff_modulus_count)

    to generate an desired amount of small primes for 128-bit security level for
    one polynomial modulus degree.

    In this example we use the default coefficient modulus for a 128-bit security
    level. Concretely, this coefficient modulus consists of only one 54-bit prime
    factor: 0x3fffffff000001.
    */
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));

    /*
    The plaintext modulus can be any positive integer, even though here we take
    it to be a power of two. In fact, in many cases one might instead want it
    to be a prime number; we will see this in later examples. The plaintext
    modulus determines the size of the plaintext data type but it also affects
    the noise budget in a freshly encrypted ciphertext and the consumption of
    noise budget in homomorphic (encrypted) multiplications. Thus, it is
    essential to try to keep the plaintext data type as small as possible for
    best performance. The noise budget in a freshly encrypted ciphertext is

        ~ log2(coeff_modulus/plain_modulus) (bits)

    and the noise budget consumption in a homomorphic multiplication is of the
    form log2(plain_modulus) + (other terms).
    The plaintext modulus does not exist in CKKS, which is shown in later examples.
    */
    parms.set_plain_modulus(512);

    /*
    Now that all parameters are set, we are ready to construct a SEALContext
    object. This is a heavy class that checks the validity and properties of the
    parameters we just set and performs several important pre-computations.
    */
    auto context = SEALContext::Create(parms);

    /*
    Print the parameters that we have chosen.
    */
    // \todo A better print_parameters, make it more visible.
    print_parameters(context);

    /*
    We are now ready to generate the secret and public keys. For this purpose
    we need an instance of the KeyGenerator class. Constructing a KeyGenerator
    automatically generates the public and secret key, which can then be read to
    local variables.
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
    We evaluate the polynomial 2x^4+4x^3+4x^2+4x+2 over an encrypted x = 6.
    The computation is done modulo the plaintext modulus 512.
    
    This examples is simple, easy to understand, but rather impractical.
    Microsoft SEAL comes with two basic encoders for the BFV scheme:
        - IntegerEncoder
        - BatchEncoder
    and one specific encoder for the CKKS scheme:
        - CKKSEncoder
    that are much more useful to encrypt integers or approximated real numbers
    and are demonstrated in later examples.
    */

    /*
    We create a plaintext as a contant polynomial, 6.
    */
    int x = 6;
    Plaintext plain_x("6");

    cout << "-- Express x = " << x << " as a plaintext polynomial 0x"
        << plain_x.to_string() << endl;

    /*
    We then encrypt the plaintext to a ciphertext.
    */
    Ciphertext encrypted_x;
    cout << "-- Encrypting plain_x: ";
    encryptor.encrypt(plain_x, encrypted_x);
    cout << "Done (encrypted_x)" << endl;

    /*
    In Microsoft SEAL, a valid ciphertext consists of two or more polynomials
    whose coefficients are integers modulo the product of the primes in
    coeff_modulus. The number of polynomials (a.k.a. size) of a ciphertext can
    be found by using Ciphertext::size().
    A freshly encrypted ciphertext always has size 2.
    */
    cout << "\tSize of freshly encrypted x: " << encrypted_x.size() << endl;

    /*
    The noise budget is not zero.
    We print the budgets in the fresh encryptions.
    */
    cout << "\tNoise budget in freshly encrypted x: "
        << decryptor.invariant_noise_budget(encrypted_x) << " bits" << endl;

    /*
    We decrypt the ciphertext to a plaintext in order to demonstrate the
    correctness of this encryption.
    */
    Plaintext decrypted_x;
    cout << "   Decrypting encrypted_x: ";
    decryptor.decrypt(encrypted_x, decrypted_x);
    cout << "Done (decrypted_x = 0x" << decrypted_x.to_string() << ")" << endl;

    /*
    When using Microsoft SEAL, one should minimize the multiplicative depth of
    the algorithm (a polynomial in this example).
    We factorize 2x^4+4x^3+4x^2+4x+2 to 2 (x+1)^2 (x^2+1) which has depth 2.
    We compute (x+1)^2 and (x^2+1) separately before multiplying them and 2.
    */

    /*
    First, compute x^2. Then add a plaintext "1". We have x^2+1.
    Multiplication consumes a lot of noise budget. This is clearly seen in the
    print-out. The user can change the plain_modulus to see its effect on the
    rate of noise budget consumption.
    */
    cout << "-- Computing x^2+1: ";
    Ciphertext x_square_plus_one;
    evaluator.square(encrypted_x, x_square_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_square_plus_one, plain_one);
    cout << "Done" << endl;

    /*
    Homomorphic multiplication results in the output ciphertext growing in size.
    More precisely, if the input ciphertexts have size M and N, then the output
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we perform squaring to observe this growth (also observe noise budget
    consumption).
    */
    cout << "\tSize of x^2+1: " << x_square_plus_one.size() << endl;
    cout << "\tNoise budget in x^2+1: "
        << decryptor.invariant_noise_budget(x_square_plus_one) << " bits" << endl;

    /*
    It does not matter that the size has grown -- decryption works as usual,
    as long as noise budget does not reach 0.
    */
    Plaintext decrypted_result;
    cout << "   Decrypting x^2+1: ";
    decryptor.decrypt(x_square_plus_one, decrypted_result);
    cout << "Done (x^2+1 = 0x" << decrypted_result.to_string() << ")" << endl;

    /*
    Second, compute x+1. Then perform squaring. We have (x+1)^2.
    */
    cout << "-- Computing (x+1)^2: ";
    Ciphertext x_plus_one_square;
    evaluator.add_plain(encrypted_x, plain_one, x_plus_one_square);
    evaluator.square_inplace(x_plus_one_square);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2: " << x_plus_one_square.size() << endl;
    cout << "\tNoise budget in (x+1)^2: "
        << decryptor.invariant_noise_budget(x_plus_one_square) << " bits" << endl;
    cout << "   Decrypting (x+1)^2: ";
    decryptor.decrypt(x_plus_one_square, decrypted_result);
    cout << "Done ((x+1)^2 = 0x" << decrypted_result.to_string() << ")" << endl;

    /*
    Third, multiply x^2+1, (x+1)^2, and 2.
    */
    cout << "-- Computing 2(x^2+1)(x+1)^2: ";
    Ciphertext encrypted_result;
    evaluator.multiply(x_square_plus_one, x_plus_one_square, encrypted_result);
    Plaintext plain_two("2");
    evaluator.multiply_plain_inplace(encrypted_result, plain_two);
    cout << "Done" << endl;
    cout << "\tSize of 2(x^2+1)(x+1)^2: " << encrypted_result.size() << endl;
    cout << "\tNoise budget in 2(x^2+1)(x+1)^2: "
        << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
    cout << "STOP: Decryption is incorrect since noise budget is zero." << endl;
    cout << endl;

    /*
    Noise budget reaches 0, which means that decyrpion will fail.
    This is bacause both ciphertexts, x^2+1 and (x+1)^2, have 3 polynomials
    due to the previous squaring operations.

    Homomorphic operations on large ciphertexts are computationally much more
    costly than on small ciphertexts. Specifically, homomorphic multiplication
    on input ciphertexts of size M and N will require O(M*N) polynomial
    multiplications to be performed, and an addition will require O(M+N)
    additions.

    Another problem is that the noise budget consumption in multiplication is
    bigger when the input ciphertexts sizes are bigger. In a complicated
    computation the contribution of the sizes to the noise budget consumption
    can actually become the dominant term.

    Relinearization reduces the size of ciphertexts after multiplication back to
    the initial size (2). Thus, relinearizing one or both inputs before the next
    multiplication or e.g. before serializing the ciphertexts, can have a huge
    positive impact on performance and noise, even though relinearization itself
    has a computational cost.

    Relinearization requires a special type of key, `relinearization keys'.
    These can be created by the KeyGenerator. To relinearize a ciphertext of
    size M >= 2 back to size 2, we actually need M-2 relinearization keys.
    Attempting to relinearize a too large ciphertext with too few
    relinearization keys will result in an exception being thrown.
    
    Relinearization is used both in the BFV and the CKKS schemes but in this
    example (for the sake of simplicity) we focus on BFV. We repeat our
    computation, but this time we relinearize after every multiplication.

    Microsoft SEAL has significantly improved relinearization, making it
    computationally more efficient and almost free of noise growth.
    Since our ciphertext never grows past size 3 (we relinearize after every
    multiplication), it suffices to generate only one relinearization key. This
    (relinearizing after every multiplication) should be the preferred approach
    in almost all cases.
    */
    /*
    First, we need to create relinearization keys. This function generates a
    single relinearization key. Another overload of KeyGenerator::relin_keys
    takes the number of keys to be generated as an argument, but one is all we
    need in this example.
    */
    cout << "-- Generating relinearization keys: ";
    auto relin_keys = keygen.relin_keys();
    cout << "Done" << endl;

    cout << "-- Computing x^2: ";
    evaluator.square(encrypted_x, x_square_plus_one);
    cout << "Done" << endl;
    cout << "\tSize of x^2: " << x_square_plus_one.size() << endl;
    cout << "-- Relinearizing x^2: ";
    evaluator.relinearize_inplace(x_square_plus_one, relin_keys);
    cout << "Done" << endl;
    cout << "\tSize of x^2 (after relinearization): "
        << x_square_plus_one.size() << endl;
    cout << "-- Computing x^2+1: ";
    evaluator.add_plain_inplace(x_square_plus_one, plain_one);
    cout << "Done" << endl;
    cout << "\tNoise budget in x^2+1: "
        << decryptor.invariant_noise_budget(x_square_plus_one) << " bits" << endl;

    cout << "-- Computing x+1: ";
    evaluator.add_plain(encrypted_x, plain_one, x_plus_one_square);
    cout << "Done" << endl;
    cout << "-- Computing (x+1)^2: ";
    evaluator.square_inplace(x_plus_one_square);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2: " << x_plus_one_square.size() << endl;
    cout << "-- Relinearizing (x+1)^2: ";
    evaluator.relinearize_inplace(x_plus_one_square, relin_keys);
    cout << "Done" << endl;
    cout << "\tSize of (x+1)^2 (after relinearization): "
        << x_plus_one_square.size() << endl;
    cout << "\tNoise budget in (x+1)^2: "
        << decryptor.invariant_noise_budget(x_plus_one_square) << " bits" << endl;

    cout << "-- Computing (x^2+1)(x+1)^2: ";
    evaluator.multiply(x_square_plus_one, x_plus_one_square, encrypted_result);
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

    /*
    Since we still have noise budget left, decryption works correctly. For x=6,
    2(x^2+1)(x+1)^2 = 3626. Since the plaintext modulus is set to 512, this
    result is reduced modulo 512. Therefore the expected output should be 42 or
    0x2A.
    */
    cout << "   Decrypting 2(x^2+1)(x+1)^2: ";
    decryptor.decrypt(encrypted_result, decrypted_result);
    cout << "Done (2(x^2+1)(x+1)^2 = 0x" << decrypted_result.to_string() << ")" << endl;
    cout << endl;
}
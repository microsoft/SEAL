// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>

#include "seal/seal.h"

using namespace std;
using namespace seal;

/*
Helper function: Prints the name of the example in a fancy banner.
*/
void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id)
{
    stream << hex << parms_id[0] << " " << parms_id[1] << " "
        << parms_id[2] << " " << parms_id[3] << dec;
    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
void print_vector(vector<T> vec, size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);

    size_t slot_count = vec.size();

    cout << fixed << setprecision(prec) << endl;
    if(slot_count <= 2 * print_size)
    {
        cout << "    [";
        for (size_t i = 0; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(max(vec.size(), 2 * print_size));
        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << " " << vec[i] << ",";
        }
        if(vec.size() > 2 * print_size)
        {
            cout << " ...,";
        }
        for (size_t i = slot_count - print_size; i < slot_count; i++)
        {
            cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    cout << endl;

    /*
    Restore the old std::cout formatting.
    */
    cout.copyfmt(old_fmt);
}

void example_bfv_basics_i();

void example_bfv_basics_ii();

void example_bfv_basics_iii();

void example_bfv_basics_iv();

void example_ckks_basics_i();

void example_ckks_basics_ii();

void example_ckks_basics_iii();

void example_bfv_performance();

void example_ckks_performance();

int main()
{
#ifdef SEAL_VERSION
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif
    while (true)
    {
        cout << "\nSEAL Examples:" << endl << endl;
        cout << " 1. BFV Basics I" << endl;
        cout << " 2. BFV Basics II" << endl;
        cout << " 3. BFV Basics III" << endl;
        cout << " 4. BFV Basics IV" << endl;
        cout << " 5. BFV Performance Test" << endl;
        cout << " 6. CKKS Basics I" << endl;
        cout << " 7. CKKS Basics II" << endl;
        cout << " 8. CKKS Basics III" << endl;
        cout << " 9. CKKS Performance Test" << endl;
        cout << " 0. Exit" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        cout << "\nTotal memory allocated from the current memory pool: "
            << (MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB" << endl;

        int selection = 0;
        cout << endl << "Run example: ";
        if (!(cin >> selection))
        {
            cout << "Invalid option." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        
        switch (selection)
        {
        case 1:
            example_bfv_basics_i();
            break;

        case 2:
            example_bfv_basics_ii();
            break;

        case 3:
            example_bfv_basics_iii();
            break;

        case 4:
            example_bfv_basics_iv();
            break;

        case 5:
            example_bfv_performance();
            break;

        case 6:
            example_ckks_basics_i();
            break;

        case 7:
            example_ckks_basics_ii();
            break;

        case 8:
            example_ckks_basics_iii();
            break;

        case 9: {
            example_ckks_performance();
            break;
        }

        case 0:
            return 0;

        default:
            cout << "Invalid option." << endl;
        }
    }

    return 0;
}

void example_bfv_basics_i()
{
    print_example_banner("Example: BFV Basics I");

    /*
    In this example we demonstrate setting up encryption parameters and other 
    relevant objects for performing simple computations on encrypted integers.

    Microsoft SEAL implements two encryption schemes: the Brakerski/Fan-Vercauteren (BFV) 
    scheme and the Cheon-Kim-Kim-Song (CKKS) scheme. In the first examples we 
    use the BFV scheme as it is far easier to understand and use than CKKS. For 
    more details on the basics of the BFV scheme, we refer the reader to the
    original paper https://eprint.iacr.org/2012/144. In truth, to achieve good 
    performance Microsoft SEAL implements the "FullRNS" optimization as described in 
    https://eprint.iacr.org/2016/510, but this optimization is invisible to 
    the user and has no security implications. We will discuss the CKKS scheme
    in later examples.

    The first task is to set up an instance of the EncryptionParameters class.
    It is critical to understand how these different parameters behave, how they
    affect the encryption scheme, performance, and the security level. There are 
    three encryption parameters that are necessary to set: 

        - poly_modulus_degree (degree of polynomial modulus);
        - coeff_modulus ([ciphertext] coefficient modulus);
        - plain_modulus (plaintext modulus).

    A fourth parameter -- noise_standard_deviation -- has a default value 3.20 
    and should not be necessary to modify unless the user has a specific reason 
    to do so and has an in-depth understanding of the security implications.

    A fifth parameter -- random_generator -- can be set to use customized random
    number generators. By default, Microsoft SEAL uses hardware-based AES in counter mode
    for pseudo-randomness with key generated using std::random_device. If the 
    AES-NI instruction set is not available, all randomness is generated from 
    std::random_device. Most academic users in particular should have little 
    reason to change this.

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
    parms.set_poly_modulus_degree(2048);

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
    of largest safe coefficient moduli for 128-bit and 192-bit security levels
    for different choices of the polynomial modulus. These default parameters 
    follow the recommendations in the Security Standard Draft available at 
    http://HomomorphicEncryption.org. The security estimates are a complicated
    topic and we highly recommend consulting with experts in the field when 
    selecting parameters. 

    Our recommended values for the coefficient modulus can be easily accessed 
    through the functions 
        
        DefaultParams::coeff_modulus_128(int)
        DefaultParams::coeff_modulus_192(int)
        DefaultParams::coeff_modulus_256(int)

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
    
        DefaultParams::small_mods_60bit(int)
        DefaultParams::small_mods_50bit(int)
        DefaultParams::small_mods_40bit(int)
        DefaultParams::small_mods_30bit(int)
    
    each of which gives access to an array of primes of the denoted size. These 
    primes are located in the source file util/globals.cpp. Again, please keep 
    in mind that the choice of coeff_modulus has a dramatic effect on security 
    and should almost always be obtained through coeff_modulus_xxx(int).

    Performance is mainly affected by the size of the polynomial modulus, and 
    the number of prime factors in the coefficient modulus; hence in some cases
    it can be important to use as few prime factors in the coefficient modulus 
    as possible.

    In this example we use the default coefficient modulus for a 128-bit security
    level. Concretely, this coefficient modulus consists of only one 54-bit prime 
    factor: 0x3fffffff000001.
    */
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(2048));

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
    */
    parms.set_plain_modulus(1 << 8);

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
    Plaintexts in the BFV scheme are polynomials with coefficients integers 
    modulo plain_modulus. This is not a very practical object to encrypt: much
    more useful would be encrypting integers or floating point numbers. For this
    we need an `encoding scheme' to convert data from integer representation to
    an appropriate plaintext polynomial representation than can subsequently be 
    encrypted. Microsoft SEAL comes with a few basic encoders for the BFV scheme:

    [IntegerEncoder]
    The IntegerEncoder encodes integers to plaintext polynomials as follows. 
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
    multiplications. BatchEncoder (discussed later) makes it easier to predict 
    encoding overflow conditions but has a stronger restriction on the size of 
    the numbers it can encode. 

    The IntegerEncoder is easy to understand and use for simple computations, 
    and can be a good starting point to learning Microsoft SEAL. However, 
    advanced users will probably prefer more efficient approaches, such as the 
    BatchEncoder or the CKKSEncoder (discussed later).

    [BatchEncoder]
    If plain_modulus is a prime congruent to 1 modulo 2*poly_modulus_degree, the 
    plaintext elements can be viewed as 2-by-(poly_modulus_degree / 2) matrices
    with elements integers modulo plain_modulus. When a desired computation can 
    be vectorized, using BatchEncoder can result in a massive performance boost
    over naively encrypting and operating on each input number separately. Thus, 
    in more complicated computations this is likely to be by far the most 
    important and useful encoder. In example_bfv_basics_iii() we show how to
    operate on encrypted matrix plaintexts.

    In this example we use the IntegerEncoder due to its simplicity. 
    */
    IntegerEncoder encoder(context);

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
    We start by encoding two integers as plaintext polynomials.
    */
    int value1 = 5;
    Plaintext plain1 = encoder.encode(value1);
    cout << "Encoded " << value1 << " as polynomial " << plain1.to_string() 
        << " (plain1)" << endl;

    int value2 = -7;
    Plaintext plain2 = encoder.encode(value2);
    cout << "Encoded " << value2 << " as polynomial " << plain2.to_string() 
        << " (plain2)" << endl;

    /*
    Encrypting the encoded values is easy.
    */
    Ciphertext encrypted1, encrypted2;
    cout << "Encrypting plain1: ";
    encryptor.encrypt(plain1, encrypted1);
    cout << "Done (encrypted1)" << endl;

    cout << "Encrypting plain2: ";
    encryptor.encrypt(plain2, encrypted2);
    cout << "Done (encrypted2)" << endl;

    /*
    To illustrate the concept of noise budget, we print the budgets in the fresh 
    encryptions.
    */
    cout << "Noise budget in encrypted1: " 
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;
    cout << "Noise budget in encrypted2: " 
        << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;

    /*
    As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2. Most 
    basic arithmetic operations come as in-place two-argument versions that
    overwrite the first argument with the result, and as three-argument versions
    taking as separate destination parameter. In most cases the in-place variants
    are slightly faster.
    */

    /*
    Negation is a unary operation and does not consume any noise budget.
    */
    evaluator.negate_inplace(encrypted1);
    cout << "Noise budget in -encrypted1: " 
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    /*
    Compute the sum of encrypted1 and encrypted2; the sum overwrites encrypted1.
    */
    evaluator.add_inplace(encrypted1, encrypted2);

    /*
    Addition sets the noise budget to the minimum of the input noise budgets. 
    In this case both inputs had roughly the same budget going in, so the output 
    (in encrypted1) has just a slightly lower budget. Depending on probabilistic 
    effects the noise growth consumption may or may not be visible when measured 
    in whole bits.
    */
    cout << "Noise budget in -encrypted1 + encrypted2: " 
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    /*
    Finally multiply with encrypted2. Again, we use the in-place version of the
    function, overwriting encrypted1 with the product.
    */
    evaluator.multiply_inplace(encrypted1, encrypted2);

    /*
    Multiplication consumes a lot of noise budget. This is clearly seen in the
    print-out. The user can change the plain_modulus to see its effect on the
    rate of noise budget consumption.
    */
    cout << "Noise budget in (-encrypted1 + encrypted2) * encrypted2: "
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    /*
    Now we decrypt and decode our result.
    */
    Plaintext plain_result;
    cout << "Decrypting result: ";
    decryptor.decrypt(encrypted1, plain_result);
    cout << "Done" << endl;

    /*
    Print the result plaintext polynomial.
    */
    cout << "Plaintext polynomial: " << plain_result.to_string() << endl;

    /*
    Decode to obtain an integer result.
    */
    cout << "Decoded integer: " << encoder.decode_int32(plain_result) << endl;
}

void example_bfv_basics_ii()
{
    print_example_banner("Example: BFV Basics II");

    /*
    In this example we explain what relinearization is, how to use it, and how 
    it affects noise budget consumption. Relinearization is used both in the BFV
    and the CKKS schemes but in this example (for the sake of simplicity) we 
    again focus on BFV.

    First we set the parameters, create a SEALContext, and generate the public
    and secret keys. We use slightly larger parameters than before to be able to 
    do more homomorphic multiplications.
    */
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(8192);

    /*
    The default coefficient modulus consists of the following primes:

        0x7fffffff380001,  0x7ffffffef00001,
        0x3fffffff000001,  0x3ffffffef40001

    The total size is 218 bits.
    */
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    parms.set_plain_modulus(1 << 10);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    We generate the public and secret keys as before. 

    There are actually two more types of keys in Microsoft SEAL: `relinearization keys' 
    and `Galois keys'. In this example we will discuss relinearization keys, and 
    Galois keys will be discussed later in example_bfv_basics_iii().
    */
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    /*
    We also set up an Encryptor, Evaluator, and Decryptor here. We will
    encrypt polynomials directly in this example, so there is no need for
    an encoder.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    We can easily construct a plaintext polynomial from a string. Again, note 
    how there is no need for encoding since the BFV scheme natively encrypts
    polynomials.
    */
    Plaintext plain1("1x^2 + 2x^1 + 3");
    Ciphertext encrypted;
    cout << "Encrypting " << plain1.to_string() << ": ";
    encryptor.encrypt(plain1, encrypted);
    cout << "Done" << endl;

    /*
    In Microsoft SEAL, a valid ciphertext consists of two or more polynomials whose 
    coefficients are integers modulo the product of the primes in coeff_modulus. 
    The current size of a ciphertext can be found using Ciphertext::size().
    A freshly encrypted ciphertext always has size 2.
    */
    cout << "Size of a fresh encryption: " << encrypted.size() << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    Homomorphic multiplication results in the output ciphertext growing in size. 
    More precisely, if the input ciphertexts have size M and N, then the output 
    ciphertext after homomorphic multiplication will have size M+N-1. In this
    case we square encrypted twice to observe this growth (also observe noise
    budget consumption).
    */
    evaluator.square_inplace(encrypted);
    cout << "Size after squaring: " << encrypted.size() << endl;
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after second squaring: " << encrypted.size() << endl;
    cout << "Noise budget after second squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    It does not matter that the size has grown -- decryption works as usual.
    Observe from the print-out that the coefficients in the plaintext have grown 
    quite large. One more squaring would cause some of them to wrap around the
    plain_modulus (0x400) and as a result we would no longer obtain the expected 
    result as an integer-coefficient polynomial. We can fix this problem to some 
    extent by increasing plain_modulus. This makes sense since we still have 
    plenty of noise budget left.
    */
    Plaintext plain2;
    decryptor.decrypt(encrypted, plain2);
    cout << "Fourth power: " << plain2.to_string() << endl;
    cout << endl;

    /*
    The problem here is that homomorphic operations on large ciphertexts are
    computationally much more costly than on small ciphertexts. Specifically,
    homomorphic multiplication on input ciphertexts of size M and N will require 
    O(M*N) polynomial multiplications to be performed, and an addition will
    require O(M+N) additions. Relinearization reduces the size of ciphertexts
    after multiplication back to the initial size (2). Thus, relinearizing one
    or both inputs before the next multiplication or e.g. before serializing the
    ciphertexts, can have a huge positive impact on performance.

    Another problem is that the noise budget consumption in multiplication is
    bigger when the input ciphertexts sizes are bigger. In a complicated
    computation the contribution of the sizes to the noise budget consumption
    can actually become the dominant term. We will point this out again below
    once we get to our example.

    Relinearization itself has both a computational cost and a noise budget cost.
    These both depend on a parameter called `decomposition bit count', which can
    be any integer at least 1 [dbc_min()] and at most 60 [dbc_max()]. A large
    decomposition bit count makes relinearization fast, but consumes more noise
    budget. A small decomposition bit count can make relinearization slower, but 
    might not change the noise budget by any observable amount.

    Relinearization requires a special type of key called `relinearization keys'.
    These can be created by the KeyGenerator for any decomposition bit count.
    To relinearize a ciphertext of size M >= 2 back to size 2, we actually need 
    M-2 relinearization keys. Attempting to relinearize a too large ciphertext 
    with too few relinearization keys will result in an exception being thrown.

    We repeat our computation, but this time relinearize after both squarings.
    Since our ciphertext never grows past size 3 (we relinearize after every
    multiplication), it suffices to generate only one relinearization key. This
    (relinearizing after every multiplication) should be the preferred approach 
    in almost all cases.

    First, we need to create relinearization keys. We use a decomposition bit 
    count of 16 here, which should be thought of as very small.

    This function generates one single relinearization key. Another overload 
    of KeyGenerator::relin_keys takes the number of keys to be generated as an 
    argument, but one is all we need in this example (see above).
    */
    auto relin_keys16 = keygen.relin_keys(16);

    cout << "Encrypting " << plain1.to_string() << ": ";
    encryptor.encrypt(plain1, encrypted);
    cout << "Done" << endl;
    cout << "Size of a fresh encryption: " << encrypted.size() << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after squaring: " << encrypted.size() << endl;
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.relinearize_inplace(encrypted, relin_keys16);
    cout << "Size after relinearization: " << encrypted.size() << endl;
    cout << "Noise budget after relinearizing (dbc = "
        << relin_keys16.decomposition_bit_count() << "): "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after second squaring: " << encrypted.size() << endl;
    cout << "Noise budget after second squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.relinearize_inplace(encrypted, relin_keys16);
    cout << "Size after relinearization: " << encrypted.size() << endl;
    cout << "Noise budget after relinearizing (dbc = "
        << relin_keys16.decomposition_bit_count() << "): "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    decryptor.decrypt(encrypted, plain2);
    cout << "Fourth power: " << plain2.to_string() << endl;
    cout << endl;

    /*
    Of course the result is still the same, but this time we actually used less 
    of our noise budget. This is not surprising for two reasons:
    
        - We used a very small decomposition bit count, which is why
          relinearization itself did not consume the noise budget by any
          observable amount;
        - Since our ciphertext sizes remain small throughout the two
          squarings, the noise budget consumption rate in multiplication
          remains as small as possible. Recall from above that operations
          on larger ciphertexts actually cause more noise growth.

    To make things more clear, we repeat the computation a third time, now using 
    the largest possible decomposition bit count (60). We are not measuring
    running time here, but relinearization with relin_keys60 (below) is much 
    faster than with relin_keys16.
    */
    auto relin_keys60 = keygen.relin_keys(DefaultParams::dbc_max());

    cout << "Encrypting " << plain1.to_string() << ": ";
    encryptor.encrypt(plain1, encrypted);
    cout << "Done" << endl;
    cout << "Size of a fresh encryption: " << encrypted.size() << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after squaring: " << encrypted.size() << endl;
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.relinearize_inplace(encrypted, relin_keys60);
    cout << "Size after relinearization: " << encrypted.size() << endl;
    cout << "Noise budget after relinearizing (dbc = "
        << relin_keys60.decomposition_bit_count() << "): "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after second squaring: " << encrypted.size() << endl;
    cout << "Noise budget after second squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.relinearize_inplace(encrypted, relin_keys60);
    cout << "Size after relinearization: " << encrypted.size() << endl;
    cout << "Noise budget after relinearizing (dbc = "
        << relin_keys60.decomposition_bit_count() << "): "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    decryptor.decrypt(encrypted, plain2);
    cout << "Fourth power: " << plain2.to_string() << endl;
    cout << endl;

    /*
    Observe from the print-out that we have now used significantly more of our
    noise budget than in the two previous runs. This is again not surprising, 
    since the first relinearization chops off a huge part of the noise budget.
    
    However, note that the second relinearization does not change the noise
    budget by any observable amount. This is very important to understand when
    optimal performance is desired: relinearization always drops the noise
    budget from the maximum (freshly encrypted ciphertext) down to a fixed 
    amount depending on the encryption parameters and the decomposition bit 
    count. On the other hand, homomorphic multiplication always consumes the
    noise budget from its current level. This is why the second relinearization
    does not change the noise budget anymore: it is already consumed past the
    fixed amount determinted by the decomposition bit count and the encryption
    parameters. 
    
    We now perform a third squaring and observe an even further compounded
    decrease in the noise budget. Again, relinearization does not consume the
    noise budget at this point by any observable amount, even with the largest
    possible decomposition bit count.
    */
    evaluator.square_inplace(encrypted);
    cout << "Size after third squaring: " << encrypted.size() << endl;
    cout << "Noise budget after third squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.relinearize_inplace(encrypted, relin_keys60);
    cout << "Size after relinearization: " << encrypted.size() << endl;
    cout << "Noise budget after relinearizing (dbc = "
        << relin_keys60.decomposition_bit_count() << "): "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    decryptor.decrypt(encrypted, plain2);
    cout << "Eighth power: " << plain2.to_string() << endl;
    
    /*
    Observe from the print-out that the polynomial coefficients are no longer
    correct as integers: they have been reduced modulo plain_modulus, and there
    was no warning sign about this. It might be necessary to carefully analyze
    the computation to make sure such overflow does not occur unexpectedly.

    These experiments suggest that an optimal strategy might be to relinearize
    first with relinearization keys with a small decomposition bit count, and 
    later with relinearization keys with a larger decomposition bit count (for 
    performance) when noise budget has already been consumed past the bound 
    determined by the larger decomposition bit count. For example, the best 
    strategy might have been to use relin_keys16 in the first relinearization 
    and relin_keys60 in the next two relinearizations for optimal noise budget 
    consumption/performance trade-off. Luckily, in most use-cases it is not so 
    critical to squeeze out every last bit of performance, especially when 
    larger parameters are used.
    */
}

void example_bfv_basics_iii()
{
    print_example_banner("Example: BFV Basics III");

    /*
    In this fundamental example we discuss and demonstrate a powerful technique 
    called `batching'. If N denotes the degree of the polynomial modulus, and T
    the plaintext modulus, then batching is automatically enabled for the BFV
    scheme when T is a prime number congruent to 1 modulo 2*N. In batching the 
    plaintexts are viewed as matrices of size 2-by-(N/2) with each element an 
    integer modulo T. Homomorphic operations act element-wise between encrypted 
    matrices, allowing the user to obtain speeds-ups of several orders of 
    magnitude in naively vectorizable computations. We demonstrate two more 
    homomorphic operations which act on encrypted matrices by rotating the rows 
    cyclically, or rotate the columns (i.e. swap the rows). These operations 
    require the construction of so-called `Galois keys', which are very similar 
    to relinearization keys.

    The batching functionality is totally optional in the BFV scheme and is 
    exposed through the BatchEncoder class. 
    */
    EncryptionParameters parms(scheme_type::BFV);

    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));

    /*
    Note that 40961 is a prime number and 2*4096 divides 40960, so batching will
    automatically be enabled for these parameters.
    */
    parms.set_plain_modulus(40961);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    We can verify that batching is indeed enabled by looking at the encryption
    parameter qualifiers created by SEALContext.
    */
    auto qualifiers = context->context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    /*
    We need to create so-called `Galois keys' for performing matrix row and 
    column rotations on encrypted matrices. Like relinearization keys, the 
    behavior of Galois keys depends on a decomposition bit count. The noise 
    budget consumption behavior of matrix row and column rotations is exactly 
    like that of relinearization (recall example_bfv_basics_ii()).

    Here we use a moderate size decomposition bit count.
    */
    auto gal_keys = keygen.galois_keys(30);

    /*
    Since we are going to do some multiplications we will also relinearize.
    */
    auto relin_keys = keygen.relin_keys(30);

    /*
    We also set up an Encryptor, Evaluator, and Decryptor here.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching is done through an instance of the BatchEncoder class so need to
    construct one.
    */
    BatchEncoder batch_encoder(context);

    /*
    The total number of batching `slots' is poly_modulus_degree. The matrices 
    we encrypt are of size 2-by-(slot_count / 2).
    */
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    Printing the matrix is a bit of a pain.
    */
    auto print_matrix = [row_size](auto &matrix)
    {
        cout << endl;

        /*
        We're not going to print every column of the matrix (there are 2048). Instead
        print this many slots from beginning and end of the matrix.
        */
        size_t print_size = 5;

        cout << "    [";
        for (size_t i = 0; i < print_size; i++)
        {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = row_size - print_size; i < row_size; i++)
        {
            cout << setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
        }
        cout << "    [";
        for (size_t i = row_size; i < row_size + print_size; i++)
        {
            cout << setw(3) << matrix[i] << ",";
        }
        cout << setw(3) << " ...,";
        for (size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
        {
            cout << setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
        }
        cout << endl;
    };

    /*
    The matrix plaintext is simply given to BatchEncoder as a flattened vector
    of numbers of size slot_count. The first row_size numbers form the first row, 
    and the rest form the second row. Here we create the following matrix:

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

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix);

    /*
    First we use BatchEncoder to compose the matrix into a plaintext.
    */
    Plaintext plain_matrix;
    batch_encoder.encode(pod_matrix, plain_matrix);

    /*
    Next we encrypt the plaintext as usual.
    */
    Ciphertext encrypted_matrix;
    cout << "Encrypting: ";
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Done" << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Operating on the ciphertext results in homomorphic operations being performed
    simultaneously in all 4096 slots (matrix elements). To illustrate this, we 
    form another plaintext matrix

        [ 1,  2,  1,  2,  1,  2, ..., 2 ]
        [ 1,  2,  1,  2,  1,  2, ..., 2 ]

    and compose it into a plaintext.
    */
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i % 2) + 1);
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2);

    /*
    We now add the second (plaintext) matrix to the encrypted one using another 
    new operation -- plain addition -- and square the sum.
    */
    cout << "Adding and squaring: ";
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);
    cout << "Done" << endl;

    /*
    How much noise budget do we have left?
    */
    cout << "Noise budget in result: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    
    /*
    We decrypt and decompose the plaintext to recover the result as a matrix.
    */
    Plaintext plain_result;
    cout << "Decrypting result: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    cout << "Done" << endl;

    vector<uint64_t> pod_result;
    batch_encoder.decode(plain_result, pod_result);

    cout << "Result plaintext matrix:" << endl;
    print_matrix(pod_result);

    /*
    Note how the operation was performed in one go for each of the elements of 
    the matrix. It is possible to achieve incredible performance improvements by 
    using this method when the computation is easily vectorizable.

    Our discussion so far could have applied just as well for a simple vector 
    data type (not matrix). Now we show how the matrix view of the plaintext can 
    be used for more functionality. Namely, it is possible to rotate the matrix 
    rows cyclically, and same for the columns (i.e. swap the two rows). For this
    we need the Galois keys that we generated earlier.

    We return to the original matrix that we started with.
    */
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Unrotated matrix: " << endl;
    print_matrix(pod_matrix);
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Now rotate the rows to the left 3 steps, decrypt, decompose, and print.
    */
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, gal_keys);
    cout << "Rotated rows 3 steps left: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Rotate columns (swap rows), decrypt, decompose, and print.
    */
    evaluator.rotate_columns_inplace(encrypted_matrix, gal_keys);
    cout << "Rotated columns: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    Rotate rows to the right 4 steps, decrypt, decompose, and print.
    */
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, gal_keys);
    cout << "Rotated rows 4 steps right: " << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    print_matrix(pod_result);
    cout << "Noise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    The output is as expected. Note how the noise budget gets a big hit in the
    first rotation, but remains almost unchanged in the next rotations. This is 
    again the same phenomenon that occurs with relinearization, where the noise 
    budget is consumed down to some bound determined by the decomposition bit 
    count and the encryption parameters. For example, after some multiplications 
    have been performed rotations come basically for free (noise budget-wise), 
    whereas they can be relatively expensive when the noise budget is nearly 
    full unless a small decomposition bit count is used, which on the other hand
    is computationally costly.
    */
}

void example_bfv_basics_iv()
{
    print_example_banner("Example: BFV Basics IV");

    /*
    In this example we describe the concept of `parms_id' in the context of the
    BFV scheme and show how modulus switching can be used for improving both
    computation and communication cost.

    We start by setting up medium size parameters for BFV as usual.
    */
    EncryptionParameters parms(scheme_type::BFV);

    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    parms.set_plain_modulus(1 << 20);

    /*
    In Microsoft SEAL a particular set of encryption parameters (excluding the random
    number generator) is identified uniquely by a SHA-3 hash of the parameters.
    This hash is called the `parms_id' and can be easily accessed and printed
    at any time. The hash will change as soon as any of the relevant parameters
    is changed.
    */
    cout << "Current parms_id: " << parms.parms_id() << endl;
    cout << "Changing plain_modulus ..." << endl;
    parms.set_plain_modulus((1 << 20) + 1);
    cout << "Current parms_id: " << parms.parms_id() << endl << endl;

    /*
    Create the context.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    All keys and ciphertext, and in the CKKS also plaintexts, carry the parms_id
    for the encryption parameters they are created with, allowing Microsoft SEAL to very 
    quickly determine whether the objects are valid for use and compatible for 
    homomorphic computations. Microsoft SEAL takes care of managing, and verifying the 
    parms_id for all objects so the user should have no reason to change it by 
    hand. 
    */
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    cout << "parms_id of public_key: " << public_key.parms_id() << endl;
    cout << "parms_id of secret_key: " << secret_key.parms_id() << endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Note how in the BFV scheme plaintexts do not carry the parms_id, but 
    ciphertexts do.
    */
    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4"); 
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    cout << "parms_id of plain: " << plain.parms_id() << " (not set)" << endl;
    cout << "parms_id of encrypted: " << encrypted.parms_id() << endl << endl;

    /*
    When SEALContext is created from a given EncryptionParameters instance,
    Microsoft SEAL automatically creates a so-called "modulus switching chain", 
    which is a chain of other encryption parameters derived from the original set.
    The parameters in the modulus switching chain are the same as the original 
    parameters with the exception that size of the coefficient modulus is
    decreasing going down the chain. More precisely, each parameter set in the
    chain attempts to remove one of the coefficient modulus primes from the
    previous set; this continues until the parameter set is no longer valid
    (e.g. plain_modulus is larger than the remaining coeff_modulus). It is easy
    to walk through the chain and access all the parameter sets. Additionally,
    each parameter set in the chain has a `chain_index' that indicates its
    position in the chain so that the last set has index 0. We say that a set
    of encryption parameters, or an object carrying those encryption parameters,
    is at a higher level in the chain than another set of parameters if its the
    chain index is bigger, i.e. it is earlier in the chain. 
    */
    for(auto context_data = context->context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << "Chain index: " << context_data->chain_index() << endl;
        cout << "parms_id: " << context_data->parms().parms_id() << endl;
        cout << "coeff_modulus primes: "; 
        cout << hex;
        for(const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl; 
        cout << "\\" << endl;
        cout << " \\-->" << endl;
    }
    cout << "End of chain reached" << endl << endl;

    /*
    Modulus switching changes the ciphertext parameters to any set down the
    chain from the current one. The function mod_switch_to_next(...) always
    switches to the next set down the chain, whereas mod_switch_to(...) switches
    to a parameter set down the chain corresponding to a given parms_id.
    */
    auto context_data = context->context_data();
    while(context_data->next_context_data()) 
    {
        cout << "Chain index: " << context_data->chain_index() << endl;
        cout << "parms_id of encrypted: " << encrypted.parms_id() << endl;
        cout << "Noise budget at this level: "
            << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
        cout << "\\" << endl;
        cout << " \\-->" << endl;
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }
    cout << "Chain index: " << context_data->chain_index() << endl;
    cout << "parms_id of encrypted: " << encrypted.parms_id() << endl;
    cout << "Noise budget at this level: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "\\" << endl;
    cout << " \\-->" << endl;
    cout << "End of chain reached" << endl << endl;

    /*
    At this point it is hard to see any benefit in doing this: we lost a huge 
    amount of noise budget (i.e. computational power) at each switch and seemed
    to get nothing in return. The ciphertext still decrypts to the exact same
    value.
    */
    decryptor.decrypt(encrypted, plain);
    cout << "Decryption: " << plain.to_string() << endl << endl;

    /*
    However, there is a hidden benefit: the size of the ciphertext depends
    linearly on the number of primes in the coefficient modulus. Thus, if there 
    is no need or intention to perform any more computations on a given 
    ciphertext, we might as well switch it down to the smallest (last) set of 
    parameters in the chain before sending it back to the secret key holder for 
    decryption.

    Also the lost noise budget is actually not as issue at all, if we do things
    right, as we will see below. First we recreate the original ciphertext (with 
    largest parameters) and perform some simple computations on it.
    */
    encryptor.encrypt(plain, encrypted);
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max()); 
    cout << "Noise budget before squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    From the print-out we see that the noise budget after these computations is 
    just slightly below the level we would have in a fresh ciphertext after one 
    modulus switch (135 bits). Surprisingly, in this case modulus switching has 
    no effect at all on the modulus.
    */ 
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "Noise budget after modulus switching: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    This means that there is no harm at all in dropping some of the coefficient
    modulus after doing enough computations. In some cases one might want to
    switch to a lower level slightly earlier, actually sacrificing some of the 
    noise budget in the process, to gain computational performance from having
    a smaller coefficient modulus. We see from the print-out that that the next 
    modulus switch should be done ideally when the noise budget reaches 81 bits. 
    */
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "Noise budget after modulus switching: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "Noise budget after modulus switching: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl << endl;

    /*
    At this point the ciphertext still decrypts correctly, has very small size,
    and the computation was as efficient as possible. Note that the decryptor
    can be used to decrypt a ciphertext at any level in the modulus switching
    chain as long as the secret key is at a higher level in the same chain.
    */
    decryptor.decrypt(encrypted, plain);
    cout << "Decryption of eighth power: " << plain.to_string() << endl << endl;

    /*
    In BFV modulus switching is not necessary and in some cases the user might
    not want to create the modulus switching chain. This can be done by passing
    a bool `false' to the SEALContext::Create(...) function as follows.
    */
    context = SEALContext::Create(parms, false);

    /*
    We can check that indeed the modulus switching chain has not been created.
    The following loop should execute only once.
    */
    for (context_data = context->context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << "Chain index: " << context_data->chain_index() << endl;
        cout << "parms_id: " << context_data->parms().parms_id() << endl;
        cout << "coeff_modulus primes: ";
        cout << hex;
        for (const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->" << endl;
    }
    cout << "End of chain reached" << endl << endl;

    /*
    It is very important to understand how this example works since in the CKKS 
    scheme modulus switching has a much more fundamental purpose and the next 
    examples will be difficult to understand unless these basic properties are 
    totally clear.
    */
}

void example_ckks_basics_i()
{
    print_example_banner("Example: CKKS Basics I");

    /*
    In this example we demonstrate using the Cheon-Kim-Kim-Song (CKKS) scheme
    for encrypting and computing on floating point numbers. For full details on 
    the CKKS scheme, we refer the reader to https://eprint.iacr.org/2016/421.
    For better performance, Microsoft SEAL implements the "FullRNS" optimization for CKKS 
    described in https://eprint.iacr.org/2018/931.
    */

    /*
    We start by creating encryption parameters for the CKKS scheme. One major
    difference to the BFV scheme is that the CKKS scheme does not use the
    plain_modulus parameter.
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
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    /*
    We also set up an Encryptor, Evaluator, and Decryptor as usual.
    */
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    /*
    To create CKKS plaintexts we need a special encoder: we cannot create them
    directly from polynomials. Note that the IntegerEncoder, FractionalEncoder, 
    and BatchEncoder cannot be used with the CKKS scheme. The CKKS scheme allows 
    encryption and approximate computation on vectors of real or complex numbers 
    which the CKKSEncoder converts into Plaintext objects. At a high level this 
    looks a lot like BatchEncoder for the BFV scheme, but the theory behind it
    is different.
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
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    Now we encode it with CKKSEncoder. The floating-point coefficients of input
    will be scaled up by the parameter `scale'; this is necessary since even in
    the CKKS scheme the plaintexts are polynomials with integer coefficients. 
    It is instructive to think of the scale as determining the bit-precision of 
    the encoding; naturally it will also affect the precision of the result. 
    
    In CKKS the message is stored modulo coeff_modulus (in BFV it is stored 
    modulo plain_modulus), so the scale must not get too close to the total size 
    of coeff_modulus. In this case our coeff_modulus is quite large (218 bits) 
    so we have little to worry about in this regard. For this example a 60-bit 
    scale is more than enough.
    */
    Plaintext plain;
    double scale = pow(2.0, 60);
    encoder.encode(input, scale, plain);

    /*
    The vector is encrypted the same was as in BFV.
    */
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    /*
    Another difference to the BFV scheme is that in CKKS also plaintexts are
    linked to specific parameter sets: they carry the corresponding parms_id.
    An overload of CKKSEncoder::encode(...) allows the caller to specify which
    parameter set in the modulus switching chain (identified by parms_id) should 
    be used to encode the plaintext. This is important as we will see later.
    */
    cout << "parms_id of plain: " << plain.parms_id() << endl;
    cout << "parms_id of encrypted: " << encrypted.parms_id() << endl << endl;

    /*
    The ciphertexts will keep track of the scales in the underlying plaintexts.
    The current scale in every plaintext and ciphertext is easy to access.
    */
    cout << "Scale in plain: " << plain.scale() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() << endl << endl;

    /*
    Basic operations on the ciphertexts are still easy to do. Here we square 
    the ciphertext, decrypt, decode, and print the result. We note also that 
    decoding returns a vector of full size (poly_modulus_degree / 2); this is 
    because of the implicit zero-padding mentioned above. 
    */
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Squared input: " << endl;
    print_vector(input);

    /*
    We notice that the results are correct. We can also print the scale in the 
    result and observe that it has increased. In fact, it is now the square of 
    the original scale (2^60). 
    */
    cout << "Scale in the square: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;

    /*
    CKKS supports modulus switching just like the BFV scheme. We can switch
    away parts of the coefficient modulus.
    */
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 

    cout << "Modulus switching ..." << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);

    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    At this point if we tried switching further Microsoft SEAL would throw an 
    exception. This is because the scale is 120 bits and after modulus switching 
    we would be down to a total coeff_modulus smaller than that, which is not 
    enough to contain the plaintext. We decrypt and decode, and observe that the 
    result is the same as before. 
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Squared input: " << endl;
    print_vector(input);

    /*
    In some cases it can be convenient to change the scale of a ciphertext by
    hand. For example, multiplying the scale by a number effectively divides the 
    underlying plaintext by that number, and vice versa. The caveat is that the 
    resulting scale can be incompatible with the scales of other ciphertexts.
    Here we divide the ciphertext by 3.
    */
    encrypted.scale() *= 3; 
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Divided by 3: " << endl;
    print_vector(input);

    /*
    Homomorphic addition and subtraction naturally require that the scales of
    the inputs are the same, but also that the encryption parameters (parms_id)
    are the same. Here we add a plaintext to encrypted. Note that a scale or
    parms_id mismatch would make Evaluator::add_plain(..) throw an exception;
    there is no problem here since we encode the plaintext just-in-time with
    exactly the right scale.
    */
    vector<double> vec_summand{ 20.2, 30.3, 40.4, 50.5 };
    cout << "Plaintext summand: " << endl;
    print_vector(vec_summand);

    /*
    Get the parms_id and scale from encrypted and do the addition.
    */
    Plaintext plain_summand;
    encoder.encode(vec_summand, encrypted.parms_id(), encrypted.scale(), 
        plain_summand);
    evaluator.add_plain_inplace(encrypted, plain_summand); 

    /*
    Decryption and decoding should give the correct result.
    */
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, input);
    cout << "Sum: " << endl;
    print_vector(input);

    /*
    Note that we have not mentioned noise budget at all. In fact, CKKS does not
    have a similar concept of a noise budget as BFV; instead, the homomorphic
    encryption noise will overlap the low-order bits of the message. This is why
    scaling is needed: the message must be moved to higher-order bits to protect
    it from the noise. Still, it is difficult to completely decouple the noise 
    from the message itself; hence the noise/error budget cannot be exactly 
    measured from a ciphertext alone. 
    */
}

void example_ckks_basics_ii()
{
    print_example_banner("Example: CKKS Basics II");

    /*
    The previous example did not really make it clear why CKKS is useful at all.
    Certainly one can scale floating-point numbers to integers, encrypt them,
    keep track of the scale, and operate on them by just using BFV. The problem
    with this approach is that the scale quickly grows larger than the size of
    the coefficient modulus, preventing further computations. The true power of 
    CKKS is that it allows the scale to be switched down (`rescaling') without 
    changing the encrypted values. 
    
    To demonstrate this, we start by setting up the same environment we had in 
    the previous example.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key); 

    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    We use a slightly smaller scale in this example.
    */
    Plaintext plain;
    double scale = pow(2.0, 60);
    encoder.encode(input, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    /*
    Print the scale and the parms_id for encrypted.
    */
    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted before squaring: " << encrypted.scale() << endl;

    /*
    We did this already in the previous example: square encrypted and observe 
    the scale growth.
    */
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "Scale in encrypted after squaring: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    Now, to prevent the scale from growing too large in subsequent operations,
    we apply rescaling.
    */
    cout << "Rescaling ..." << endl << endl;
    evaluator.rescale_to_next_inplace(encrypted);

    /*
    Rescaling changes the coefficient modulus as modulus switching does. These
    operations are in fact very closely related. Moreover, the scale indeed has 
    been significantly reduced: rescaling divides the scale by the coefficient
    modulus prime that was switched away. Since our coefficient modulus in this
    case consisted of the primes (see seal/utils/global.cpp)

        0x7fffffff380001,  0x7ffffffef00001,
        0x3fffffff000001,  0x3ffffffef40001,

    the last of which is 54 bits, the bit-size of the scale was reduced by 
    precisely 54 bits. Finer granularity rescaling would require smaller primes
    to be used, but this might lead to performance problems as the computational 
    cost of homomorphic operations and the size of ciphertexts depends linearly 
    on the number of primes in coeff_modulus.
    */
    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    We can even compute the fourth power of the input. Note that it is very
    important to first relinearize and then rescale. Trying to do these two
    operations in the opposite order will make Microsoft SEAL throw and exception.
    */
    cout << "Squaring and rescaling ..." << endl << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted);

    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    At this point our scale is 78 bits and the coefficient modulus is 110 bits.
    This means that we cannot square the result anymore, but if we rescale once
    more and then square, things should work out better. We cannot relinearize
    with relin_keys at this point due to the large decomposition bit count we 
    used: the noise from relinearization would completely destroy our result 
    due to the small scale we are at.
    */
    cout << "Rescaling and squaring (no relinearization) ..." << endl << endl;
    evaluator.rescale_to_next_inplace(encrypted);
    evaluator.square_inplace(encrypted);

    cout << "Chain index of (encryption parameters of) encrypted: " 
        << context->context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() 
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl; 
    cout << endl;

    /*
    We decrypt, decode, and print the results.
    */
    decryptor.decrypt(encrypted, plain);
    vector<double> result;
    encoder.decode(plain, result);
    cout << "Eighth powers: " << endl;
    print_vector(result);

    /*
    We have gone pretty low in the scale at this point and can no longer expect
    to get entirely accurate results. Still, our results are quite accurate. 
    */
    vector<double> precise_result{};
    transform(input.begin(), input.end(), back_inserter(precise_result), 
        [](auto in) { return pow(in, 8); });
    cout << "Precise result: " << endl;
    print_vector(precise_result);
}

void example_ckks_basics_iii()
{
    print_example_banner("Example: CKKS Basics III");

    /*
    In this example we demonstrate evaluating a polynomial function on
    floating-point input data. The challenges we encounter will be related to
    matching scales and encryption parameters when adding together terms of
    different degrees in the polynomial evaluation. We start by setting up an
    environment similar to what we had in the above examples.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);

    /*
    In this example we decide to use four 40-bit moduli for more flexible 
    rescaling. Note that 4*40 bits = 160 bits, which is well below the size of 
    the default coefficient modulus (see seal/util/globals.cpp). It is always
    more secure to use a smaller coefficient modulus while keeping the degree of
    the polynomial modulus fixed. Since the coeff_mod_128(8192) default 218-bit 
    coefficient modulus achieves already a 128-bit security level, this 160-bit 
    modulus must be much more secure.

    We use the DefaultParams::small_mods_40bit(int) function to get primes from 
    a hard-coded list of 40-bit prime numbers; it is important that all primes 
    used for the coefficient modulus are distinct.
    */
    parms.set_coeff_modulus({
        DefaultParams::small_mods_40bit(0), 
        DefaultParams::small_mods_40bit(1),
        DefaultParams::small_mods_40bit(2), 
        DefaultParams::small_mods_40bit(3) });

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys(DefaultParams::dbc_max());

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    In this example our goal is to evaluate the polynomial PI*x^3 + 0.4x + 1 on 
    an encrypted input x for 4096 equidistant points x in the interval [0, 1]. 
    */
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0, step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);
    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl << endl;

    /*
    Now encode and encrypt the input using the last of the coeff_modulus primes 
    as the scale for a reason that will become clear soon.
    */
    auto scale = static_cast<double>(parms.coeff_modulus().back().value());
    Plaintext plain_x;
    encoder.encode(input, scale, plain_x);
    Ciphertext encrypted_x1;
    encryptor.encrypt(plain_x, encrypted_x1);

    /*
    We create plaintext elements for PI, 0.4, and 1, using an overload of
    CKKSEncoder::encode(...) that encodes the given floating-point value to
    every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    /*
    To compute x^3 we first compute x^2, relinearize, and rescale.
    */
    Ciphertext encrypted_x3;
    evaluator.square(encrypted_x1, encrypted_x3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_x3);

    /*
    Now encrypted_x3 is at different encryption parameters than encrypted_x1, 
    preventing us from multiplying them together to compute x^3. We could simply 
    switch encrypted_x1 down to the next parameters in the modulus switching 
    chain. Since we still need to multiply the x^3 term with PI (plain_coeff3), 
    we instead compute PI*x first and multiply that with x^2 to obtain PI*x^3.
    This product poses no problems since both inputs are at the same scale and 
    use the same encryption parameters. We rescale afterwards to change the 
    scale back to 40 bits, which will also drop the coefficient modulus down to 
    120 bits. 
    */
    Ciphertext encrypted_x1_coeff3;
    evaluator.multiply_plain(encrypted_x1, plain_coeff3, encrypted_x1_coeff3);
    evaluator.rescale_to_next_inplace(encrypted_x1_coeff3);

    /*
    Since both encrypted_x3 and encrypted_x1_coeff3 now have the same scale and 
    use same encryption parameters, we can multiply them together. We write the 
    result to encrypted_x3.
    */
    evaluator.multiply_inplace(encrypted_x3, encrypted_x1_coeff3);
    evaluator.relinearize_inplace(encrypted_x3, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_x3);

    /*
    Next we compute the degree one term. All this requires is one multiply_plain 
    with plain_coeff1. We overwrite encrypted_x1 with the result.
    */
    evaluator.multiply_plain_inplace(encrypted_x1, plain_coeff1);
    evaluator.rescale_to_next_inplace(encrypted_x1);

    /*
    Now we would hope to compute the sum of all three terms. However, there is 
    a serious problem: the encryption parameters used by all three terms are 
    different due to modulus switching from rescaling. 
    */
    cout << "Parameters used by all three terms are different:" << endl;
    cout << "Modulus chain index for encrypted_x3: "
        << context->context_data(encrypted_x3.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for encrypted_x1: "
        << context->context_data(encrypted_x1.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for plain_coeff0: "
        << context->context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. If we denote 
    the primes in coeff_modulus as q1, q2, q3, q4 (order matters here), then all
    fresh encodings start with a scale equal to q4 (this was a choice we made 
    above). After the computations above the scale in encrypted_x3 is q4^2/q3:

        * The product x^2 has scale q4^2;
        * The produt PI*x has scale q4^2;
        * Rescaling both of these by q4 (last prime) results in scale q4; 
        * Multiplication to obtain PI*x^3 raises the scale to q4^2;
        * Rescaling by q3 (last prime) yields a scale of q4^2/q3.

    The scale in both encrypted_x1 and plain_coeff0 is just q4.
    */
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in encrypted_x3: " << encrypted_x3.scale() << endl;
    cout << "Scale in encrypted_x1: " << encrypted_x1.scale() << endl;
    cout << "Scale in plain_coeff0: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are a couple of ways to fix this this problem. Since q4 and q3 are 
    really close to each other, we could simply "lie" to Microsoft SEAL and set 
    the scales to be the same. For example, changing the scale of encrypted_x3 to 
    be q4 simply means that we scale the value of encrypted_x3 by q4/q3 which is 
    very close to 1; this should not result in any noticeable error. 
    
    Another option would be to encode 1 with scale q4, perform a multiply_plain 
    with encrypted_x1, and finally rescale. In this case we would additionally 
    make sure to encode 1 with the appropriate encryption parameters (parms_id). 
    
    A third option would be to initially encode plain_coeff1 with scale q4^2/q3. 
    Then, after multiplication with encrypted_x1 and rescaling, the result would 
    have scale q4^2/q3. Since encoding can be computationally costly, this may 
    not be a realistic option in some cases.
    
    In this example we will use the first (simplest) approach and simply change
    the scale of encrypted_x3.
    */
    encrypted_x3.scale() = encrypted_x1.scale();

    /*
    We still have a problem with mismatching encryption parameters. This is easy
    to fix by using traditional modulus switching (no rescaling). Note that we
    use here the Evaluator::mod_switch_to_inplace(...) function to switch to
    encryption parameters down the chain with a specific parms_id.
    */
    evaluator.mod_switch_to_inplace(encrypted_x1, encrypted_x3.parms_id());
    evaluator.mod_switch_to_inplace(plain_coeff0, encrypted_x3.parms_id());

    /*
    All three ciphertexts are now compatible and can be added.
    */
    Ciphertext encrypted_result;
    evaluator.add(encrypted_x3, encrypted_x1, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    Print the chain index and scale for encrypted_result. 
    */
    cout << "Modulus chain index for encrypted_result: "
        << context->context_data(encrypted_result.parms_id())
        ->chain_index() << endl;
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in encrypted_result: " << encrypted_result.scale();
    cout.copyfmt(old_fmt);
    cout << " (" << log2(encrypted_result.scale()) << " bits)" << endl;

    /*
    We decrypt, decode, and print the result.
    */
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Result of PI*x^3 + 0.4x + 1:" << endl;
    print_vector(result, 3, 7);

    /*
    At this point if we wanted to multiply encrypted_result one more time, the 
    other multiplicand would have to have scale less than 40 bits, otherwise 
    the scale would become larger than the coeff_modulus itself. 
    */
    cout << "Current coeff_modulus size for encrypted_result: "
        << context->context_data(encrypted_result.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl << endl; 
    
    /*
    A very extreme case for multiplication is where we multiply a ciphertext 
    with a vector of values that are all the same integer. For example, let us 
    multiply encrypted_result by 7. In this case we do not need any scaling in 
    the multiplicand due to a different (much simpler) encoding process.
    */
    Plaintext plain_integer_scalar;
    encoder.encode(7, encrypted_result.parms_id(), plain_integer_scalar);
    evaluator.multiply_plain_inplace(encrypted_result, plain_integer_scalar);

    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Scale in plain_integer_scalar scale: " 
        << plain_integer_scalar.scale() << endl;
    cout << "Scale in encrypted_result: " << encrypted_result.scale() << endl;
    cout.copyfmt(old_fmt);

    /*
    We decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result of 7 * (PI*x^3 + 0.4x + 1):" << endl;
    print_vector(result, 3, 7);

    /*
    Finally, we show how to apply vector rotations on the encrypted data. This
    is very similar to how matrix rotations work in the BFV scheme. We try this
    with three sizes of Galois keys. In some cases it is desirable for memory
    reasons to create Galois keys that support only specific rotations. This can
    be done by passing to KeyGenerator::galois_keys(...) a vector of signed 
    integers specifying the desired rotation step counts. Here we create Galois
    keys that only allow cyclic rotation by a single step (at a time) to the left.
    */
    auto gal_keys30 = keygen.galois_keys(30, vector<int>{ 1 });
    auto gal_keys15 = keygen.galois_keys(15, vector<int>{ 1 });

    Ciphertext rotated_result;
    evaluator.rotate_vector(encrypted_result, 1, gal_keys15, rotated_result); 
    decryptor.decrypt(rotated_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result rotated with dbc 15:" << endl;
    print_vector(result, 3, 7);

    evaluator.rotate_vector(encrypted_result, 1, gal_keys30, rotated_result); 
    decryptor.decrypt(rotated_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result rotated with dbc 30:" << endl;
    print_vector(result, 3, 5);

    /*
    We notice that the using the smallest decomposition bit count introduces 
    the least amount of error in the result. The problem is that our scale at 
    this point is very small -- only 40 bits -- so a rotation with decomposition 
    bit count 30 or bigger already destroys most or all of the message bits. 
    Ideally rotations would be performed right after multiplications before any
    rescaling takes place. This way the scale is as large as possible and the
    additive noise coming from the rotation (or relinearization) will be totally
    shadowed by the large scale, and subsequently scaled down by the following 
    rescaling. Of course this may not always be possible to arrange.

    We did not show any computations on complex numbers in these examples, but
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications behave just as one would expect. It is also possible
    to complex conjugate the values in a ciphertext by using the functions
    Evaluator::complex_conjugate[_inplace](...).
    */
}

void example_bfv_performance()
{
    print_example_banner("Example: BFV Performance Test");

    /*
    In this example we time all the basic operations. We use the following 
    lambda function to run the test.
    */
    auto performance_test = [](auto context)
    {
        chrono::high_resolution_clock::time_point time_start, time_end;

        print_parameters(context);
        auto &curr_parms = context->context_data()->parms();
        auto &plain_modulus = curr_parms.plain_modulus();
        size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

        /*
        Set up keys. For both relinearization and rotations we use a large 
        decomposition bit count for best possible computational performance.
        */
        cout << "Generating secret/public keys: ";
        KeyGenerator keygen(context);
        cout << "Done" << endl;

        auto secret_key = keygen.secret_key();
        auto public_key = keygen.public_key();

        /*
        Generate relinearization keys.
        */
        int dbc = DefaultParams::dbc_max();
        cout << "Generating relinearization keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto relin_keys = keygen.relin_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        /*
        Generate Galois keys. In larger examples the Galois keys can use 
        a significant amount of memory, which can be a problem in constrained 
        systems. The user should try enabling some of the larger runs of the 
        test (see below) and to observe their effect on the memory pool
        allocation size. The key generation can also take a significant amount 
        of time, as can be observed from the print-out.
        */
        if (!context->context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }
        cout << "Generating Galois keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto gal_keys = keygen.galois_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        BatchEncoder batch_encoder(context);
        IntegerEncoder encoder(context);

        /*
        These will hold the total times used by each operation.
        */
        chrono::microseconds time_batch_sum(0);
        chrono::microseconds time_unbatch_sum(0);
        chrono::microseconds time_encrypt_sum(0);
        chrono::microseconds time_decrypt_sum(0);
        chrono::microseconds time_add_sum(0);
        chrono::microseconds time_multiply_sum(0);
        chrono::microseconds time_multiply_plain_sum(0);
        chrono::microseconds time_square_sum(0);
        chrono::microseconds time_relinearize_sum(0);
        chrono::microseconds time_rotate_rows_one_step_sum(0);
        chrono::microseconds time_rotate_rows_random_sum(0);
        chrono::microseconds time_rotate_columns_sum(0);

        /*
        How many times to run the test?
        */
        int count = 10;

        /*
        Populate a vector of values to batch.
        */
        vector<uint64_t> pod_vector;
        random_device rd;
        for (size_t i = 0; i < batch_encoder.slot_count(); i++)
        {
            pod_vector.push_back(rd() % plain_modulus.value());
        }

        cout << "Running tests ";
        for (int i = 0; i < count; i++)
        {
            /*
            [Batching]
            There is nothing unusual here. We batch our random plaintext matrix 
            into the polynomial. The user can try changing the decomposition bit 
            count to something smaller to see the effect. Note how the plaintext 
            we create is of the exactly right size so unnecessary reallocations 
            are avoided.
            */
            Plaintext plain(curr_parms.poly_modulus_degree(), 0);
            time_start = chrono::high_resolution_clock::now();
            batch_encoder.encode(pod_vector, plain);
            time_end = chrono::high_resolution_clock::now();
            time_batch_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Unbatching]
            We unbatch what we just batched.
            */
            vector<uint64_t> pod_vector2(batch_encoder.slot_count());
            time_start = chrono::high_resolution_clock::now();
            batch_encoder.decode(plain, pod_vector2);
            time_end = chrono::high_resolution_clock::now();
            time_unbatch_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
            if (pod_vector2 != pod_vector)
            {
                throw runtime_error("Batch/unbatch failed. Something is wrong.");
            }

            /*
            [Encryption]
            We make sure our ciphertext is already allocated and large enough to 
            hold the encryption with these encryption parameters. We encrypt our
            random batched matrix here.
            */
            Ciphertext encrypted(context);
            time_start = chrono::high_resolution_clock::now();
            encryptor.encrypt(plain, encrypted);
            time_end = chrono::high_resolution_clock::now();
            time_encrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Decryption]
            We decrypt what we just encrypted.
            */
            Plaintext plain2(poly_modulus_degree, 0);
            time_start = chrono::high_resolution_clock::now();
            decryptor.decrypt(encrypted, plain2);
            time_end = chrono::high_resolution_clock::now();
            time_decrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);
            if (plain2 != plain)
            {
                throw runtime_error("Encrypt/decrypt failed. Something is wrong.");
            }

            /*
            [Add]
            We create two ciphertexts that are both of size 2, and perform a few
            additions with them.
            */
            Ciphertext encrypted1(context);
            encryptor.encrypt(encoder.encode(i), encrypted1);
            Ciphertext encrypted2(context);
            encryptor.encrypt(encoder.encode(i + 1), encrypted2);
            time_start = chrono::high_resolution_clock::now();
            evaluator.add_inplace(encrypted1, encrypted1);
            evaluator.add_inplace(encrypted2, encrypted2);
            evaluator.add_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_add_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 3;

            /*
            [Multiply]
            We multiply two ciphertexts of size 2. Since the size of the result
            will be 3, and will overwrite the first argument, we reserve first
            enough memory to avoid reallocating during multiplication.
            */
            encrypted1.reserve(3);
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Multiply Plain]
            We multiply a ciphertext of size 2 with a random plaintext. Recall
            that multiply_plain does not change the size of the ciphertext so we 
            use encrypted2 here, which still has size 2.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_plain_inplace(encrypted2, plain);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Square]
            We continue to use the size 2 ciphertext encrypted2. Now we square 
            it; this should be faster than generic homomorphic multiplication.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.square_inplace(encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_square_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Relinearize]
            Time to get back to encrypted1; at this point it still has size 3. 
            We now relinearize it back to size 2. Since the allocation is 
            currently big enough to contain a ciphertext of size 3, no costly
            reallocations are needed in the process.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.relinearize_inplace(encrypted1, relin_keys);
            time_end = chrono::high_resolution_clock::now();
            time_relinearize_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Rows One Step]
            We rotate matrix rows by one step left and measure the time.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_rows_inplace(encrypted, 1, gal_keys);
            evaluator.rotate_rows_inplace(encrypted, -1, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_rows_one_step_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 2;

            /*
            [Rotate Rows Random]
            We rotate matrix rows by a random number of steps. This is more
            expensive than rotating by just one step.
            */
            size_t row_size = batch_encoder.slot_count() / 2;
            int random_rotation = static_cast<int>(rd() % row_size);
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_rows_inplace(encrypted, random_rotation, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_rows_random_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Columns]
            Nothing surprising here.
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_columns_inplace(encrypted, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_columns_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            Print a dot to indicate progress.
            */
            cout << ".";
            cout.flush();
        }

        cout << " Done" << endl << endl;
        cout.flush();

        auto avg_batch = time_batch_sum.count() / count;
        auto avg_unbatch = time_unbatch_sum.count() / count;
        auto avg_encrypt = time_encrypt_sum.count() / count;
        auto avg_decrypt = time_decrypt_sum.count() / count;
        auto avg_add = time_add_sum.count() / count;
        auto avg_multiply = time_multiply_sum.count() / count;
        auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
        auto avg_square = time_square_sum.count() / count;
        auto avg_relinearize = time_relinearize_sum.count() / count;
        auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / count;
        auto avg_rotate_rows_random = time_rotate_rows_random_sum.count() / count;
        auto avg_rotate_columns = time_rotate_columns_sum.count() / count;

        cout << "Average batch: " << avg_batch << " microseconds" << endl;
        cout << "Average unbatch: " << avg_unbatch << " microseconds" << endl;
        cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
        cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
        cout << "Average add: " << avg_add << " microseconds" << endl;
        cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
        cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
        cout << "Average square: " << avg_square << " microseconds" << endl;
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rotate rows one step: " << avg_rotate_rows_one_step << " microseconds" << endl;
        cout << "Average rotate rows random: " << avg_rotate_rows_random << " microseconds" << endl;
        cout << "Average rotate columns: " << avg_rotate_columns << " microseconds" << endl;
        cout.flush();
    };

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
    parms.set_plain_modulus(786433);
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    parms.set_plain_modulus(786433);
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));
    parms.set_plain_modulus(786433);
    performance_test(SEALContext::Create(parms));

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // parms.set_poly_modulus_degree(32768);
    // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(32768));
    // parms.set_plain_modulus(786433);
    // performance_test(SEALContext::Create(parms));
}

void example_ckks_performance()
{
    print_example_banner("Example: CKKS Performance Test");

    /*
    In this example we time all the basic operations. We use the following 
    lambda function to run the test. This is largely similar to the function
    in the previous example.
    */
    auto performance_test = [](auto context)
    {
        chrono::high_resolution_clock::time_point time_start, time_end;

        print_parameters(context);
        auto &curr_parms = context->context_data()->parms();
        size_t poly_modulus_degree = curr_parms.poly_modulus_degree();

        cout << "Generating secret/public keys: ";
        KeyGenerator keygen(context);
        cout << "Done" << endl;

        auto secret_key = keygen.secret_key();
        auto public_key = keygen.public_key();

        int dbc = DefaultParams::dbc_max();
        cout << "Generating relinearization keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto relin_keys = keygen.relin_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        auto time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context->context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }
        cout << "Generating Galois keys (dbc = " << dbc << "): ";
        time_start = chrono::high_resolution_clock::now();
        auto gal_keys = keygen.galois_keys(dbc);
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        Encryptor encryptor(context, public_key);
        Decryptor decryptor(context, secret_key);
        Evaluator evaluator(context);
        CKKSEncoder ckks_encoder(context);

        chrono::microseconds time_encode_sum(0);
        chrono::microseconds time_decode_sum(0);
        chrono::microseconds time_encrypt_sum(0);
        chrono::microseconds time_decrypt_sum(0);
        chrono::microseconds time_add_sum(0);
        chrono::microseconds time_multiply_sum(0);
        chrono::microseconds time_multiply_plain_sum(0);
        chrono::microseconds time_square_sum(0);
        chrono::microseconds time_relinearize_sum(0);
        chrono::microseconds time_rescale_sum(0);
        chrono::microseconds time_rotate_one_step_sum(0);
        chrono::microseconds time_rotate_random_sum(0);
        chrono::microseconds time_conjugate_sum(0);

        /*
        How many times to run the test?
        */
        int count = 10;

        /*
        Populate a vector of floating-point values to batch.
        */
        vector<double> pod_vector;
        random_device rd;
        for (size_t i = 0; i < ckks_encoder.slot_count(); i++)
        {
            pod_vector.push_back(1.001 * static_cast<double>(i));
        }

        cout << "Running tests ";
        for (int i = 0; i < count; i++)
        {
            /*
            [Encoding]
            */
            Plaintext plain(curr_parms.poly_modulus_degree() * 
                curr_parms.coeff_modulus().size(), 0);
            time_start = chrono::high_resolution_clock::now();
            ckks_encoder.encode(pod_vector, 
                static_cast<double>(curr_parms.coeff_modulus().back().value()), plain);
            time_end = chrono::high_resolution_clock::now();
            time_encode_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Decoding]
            */
            vector<double> pod_vector2(ckks_encoder.slot_count());
            time_start = chrono::high_resolution_clock::now();
            ckks_encoder.decode(plain, pod_vector2);
            time_end = chrono::high_resolution_clock::now();
            time_decode_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Encryption]
            */
            Ciphertext encrypted(context);
            time_start = chrono::high_resolution_clock::now();
            encryptor.encrypt(plain, encrypted);
            time_end = chrono::high_resolution_clock::now();
            time_encrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Decryption]
            */
            Plaintext plain2(poly_modulus_degree, 0);
            time_start = chrono::high_resolution_clock::now();
            decryptor.decrypt(encrypted, plain2);
            time_end = chrono::high_resolution_clock::now();
            time_decrypt_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Add]
            */
            Ciphertext encrypted1(context);
            ckks_encoder.encode(i + 1, plain);
            encryptor.encrypt(plain, encrypted1);
            Ciphertext encrypted2(context);
            ckks_encoder.encode(i + 1, plain2);
            encryptor.encrypt(plain2, encrypted2);
            time_start = chrono::high_resolution_clock::now();
            evaluator.add_inplace(encrypted1, encrypted1);
            evaluator.add_inplace(encrypted2, encrypted2);
            evaluator.add_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_add_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 3;

            /*
            [Multiply]
            */
            encrypted1.reserve(3);
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_inplace(encrypted1, encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Multiply Plain]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.multiply_plain_inplace(encrypted2, plain);
            time_end = chrono::high_resolution_clock::now();
            time_multiply_plain_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Square]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.square_inplace(encrypted2);
            time_end = chrono::high_resolution_clock::now();
            time_square_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Relinearize]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.relinearize_inplace(encrypted1, relin_keys);
            time_end = chrono::high_resolution_clock::now();
            time_relinearize_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rescale]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rescale_to_next_inplace(encrypted1);
            time_end = chrono::high_resolution_clock::now();
            time_rescale_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Rotate Vector]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, 1, gal_keys);
            evaluator.rotate_vector_inplace(encrypted, -1, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_one_step_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start) / 2;

            /*
            [Rotate Vector Random]
            */
            int random_rotation = static_cast<int>(rd() % ckks_encoder.slot_count());
            time_start = chrono::high_resolution_clock::now();
            evaluator.rotate_vector_inplace(encrypted, random_rotation, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_rotate_random_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            [Complex Conjugate]
            */
            time_start = chrono::high_resolution_clock::now();
            evaluator.complex_conjugate_inplace(encrypted, gal_keys);
            time_end = chrono::high_resolution_clock::now();
            time_conjugate_sum += chrono::duration_cast<
                chrono::microseconds>(time_end - time_start);

            /*
            Print a dot to indicate progress.
            */
            cout << ".";
            cout.flush();
        }

        cout << " Done" << endl << endl;
        cout.flush();

        auto avg_encode = time_encode_sum.count() / count;
        auto avg_decode = time_decode_sum.count() / count;
        auto avg_encrypt = time_encrypt_sum.count() / count;
        auto avg_decrypt = time_decrypt_sum.count() / count;
        auto avg_add = time_add_sum.count() / count;
        auto avg_multiply = time_multiply_sum.count() / count;
        auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
        auto avg_square = time_square_sum.count() / count;
        auto avg_relinearize = time_relinearize_sum.count() / count;
        auto avg_rescale = time_rescale_sum.count() / count;
        auto avg_rotate_one_step = time_rotate_one_step_sum.count() / count;
        auto avg_rotate_random = time_rotate_random_sum.count() / count;
        auto avg_conjugate = time_conjugate_sum.count() / count;

        cout << "Average encode: " << avg_encode << " microseconds" << endl;
        cout << "Average decode: " << avg_decode << " microseconds" << endl;
        cout << "Average encrypt: " << avg_encrypt << " microseconds" << endl;
        cout << "Average decrypt: " << avg_decrypt << " microseconds" << endl;
        cout << "Average add: " << avg_add << " microseconds" << endl;
        cout << "Average multiply: " << avg_multiply << " microseconds" << endl;
        cout << "Average multiply plain: " << avg_multiply_plain << " microseconds" << endl;
        cout << "Average square: " << avg_square << " microseconds" << endl;
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step << " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
        cout.flush();
    };

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(4096));
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    performance_test(SEALContext::Create(parms));

    cout << endl;
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));
    performance_test(SEALContext::Create(parms));

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // parms.set_poly_modulus_degree(32768);
    // parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(32768));
    // performance_test(SEALContext::Create(parms));
}

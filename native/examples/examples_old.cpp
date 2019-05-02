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
    evaluator.multiply_inplace(encrypted1, encrypted2);
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

    cout << "Size of a fresh encryption: " << encrypted.size() << endl;
    cout << "Noise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after squaring: " << encrypted.size() << endl;
    cout << "Noise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    evaluator.square_inplace(encrypted);
    cout << "Size after second squaring: " << encrypted.size() << endl;
    cout << "Noise budget after second squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
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
    Create the context.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    In Microsoft SEAL a particular set of encryption parameters (excluding the
    random number generator) is identified uniquely by a SHA-3 hash of the
    parameters. This hash is called the `parms_id' and can be easily accessed
    and printed at any time. The hash will change as soon as any of the relevant
    parameters is changed.
    */

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
    for(auto context_data = context->first_context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << "Chain index: " << context_data->chain_index() << endl;
        cout << "parms_id: " << context_data->parms_id() << endl;
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
    auto context_data = context->first_context_data();
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
    auto relin_keys = keygen.relin_keys();
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
    no effect at all on the noise budget.
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

    /*
    At this point the ciphertext still decrypts correctly, has very small size,
    and the computation was as efficient as possible. Note that the decryptor
    can be used to decrypt a ciphertext at any level in the modulus switching
    chain as long as the secret key is at a higher level in the same chain.
    */
    decryptor.decrypt(encrypted, plain);
    cout << "Decryption of fourth power: " << plain.to_string() << endl << endl;

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
    for (context_data = context->first_context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << "Chain index: " << context_data->chain_index() << endl;
        cout << "parms_id: " << context_data->parms_id() << endl;
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
    CKKS supports modulus switching just like the BFV scheme. We can switch
    away parts of the coefficient modulus.
    */
    cout << "Current coeff_modulus size: "
        << context->get_context_data(encrypted.parms_id())->
            total_coeff_modulus_bit_count() << " bits" << endl;

    cout << "Modulus switching ..." << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);

    cout << "Current coeff_modulus size: "
        << context->get_context_data(encrypted.parms_id())->
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
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(16384));

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

    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "Input vector: " << endl;
    print_vector(input);

    /*
    We use a slightly larger scale in this example.
    */
    Plaintext plain;
    double scale = pow(2.0, 80);
    encoder.encode(input, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    /*
    Print the scale and the parms_id for encrypted.
    */
    cout << "Chain index of (encryption parameters of) encrypted: "
        << context->get_context_data(encrypted.parms_id())->chain_index() << endl;
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
        << context->get_context_data(encrypted.parms_id())->
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
        << context->get_context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale()
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->get_context_data(encrypted.parms_id())->
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
        << context->get_context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale()
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->get_context_data(encrypted.parms_id())->
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
        << context->get_context_data(encrypted.parms_id())->chain_index() << endl;
    cout << "Scale in encrypted: " << encrypted.scale()
        << " (" << log2(encrypted.scale()) << " bits)" << endl;
    cout << "Current coeff_modulus size: "
        << context->get_context_data(encrypted.parms_id())->
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
        DefaultParams::small_mods_40bit(3),
        DefaultParams::small_mods_40bit(4) });

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
    // \todo GET RID OF THIS and use some simpler scale
    EncryptionParameters current_parms = context->first_context_data()->parms();
    auto scale = static_cast<double>(current_parms.coeff_modulus().back().value());
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
        << context->get_context_data(encrypted_x3.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for encrypted_x1: "
        << context->get_context_data(encrypted_x1.parms_id())->chain_index() << endl;
    cout << "Modulus chain index for plain_coeff0: "
        << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
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
        << context->get_context_data(encrypted_result.parms_id())
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
        << context->get_context_data(encrypted_result.parms_id())->
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
    auto gal_keys = keygen.galois_keys(vector<int>{ 1 });

    Ciphertext rotated_result;
    evaluator.rotate_vector(encrypted_result, 1, gal_keys, rotated_result);
    decryptor.decrypt(rotated_result, plain_result);
    encoder.decode(plain_result, result);
    cout << "Result rotated:" << endl;
    print_vector(result, 3, 7);

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

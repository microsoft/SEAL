// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

void example_ckks_basics_i()
{
    /*
    The ciphertexts will keep track of the scales in the underlying plaintexts.
    The current scale in every plaintext and ciphertext is easy to access.
    */
    cout << "Scale in plain: " << plain.scale() << endl;
    cout << "Scale in encrypted: " << encrypted.scale() << endl << endl;

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


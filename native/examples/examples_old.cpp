// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.


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


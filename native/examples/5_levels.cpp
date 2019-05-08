// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_levels()
{
    print_example_banner("Example: Levels");

    /*
    In this examples we describe the concept of levels in BFV and CKKS and the
    related objects that represent them in Microsoft SEAL.

    In applications built with homomorphic encryption, the multiplicative depth
    of an application or a circuit is very critical. First, multiplications
    contribute a lot to noise growth. Second, a relinearization is generally
    required after multiplications and it is costly (see example_basic_bfv).
    Third, in CKKS after each multiplication the scale in a ciphertext needs to
    be adjusted. Fourth, with modulus switching ciphertexts at different
    multiplicative levels have different ring structure (coefficient modulus).
    Therefore, keeping track of levels in homomorphic evaluation is necessary
    and benificial to performance.

    In Microsoft SEAL a particular set of encryption parameters (excluding the
    random number generator) is identified uniquely by a SHA-3 hash of the
    parameters. This hash is called the `parms_id' and can be easily accessed
    and printed at any time. The hash will change as soon as any of the relevant
    parameters is changed.

    Each set of encryption parameters involve unique precomputation which are
    stored in a SEALContext::ContextData object. Its `parms_id' is used to
    identify and access this object in a SEALContext object. The SEALContext
    contains a chain of SEALContext::ContextData objects each of which contains
    the precomputed data for the encryption parameters at the corresponding level.
    */
    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(8192);

    /*
    For a given polynomial modulus degree, we may choose a number of primes as
    long as they pass validity check.
    */
    vector<SmallModulus> primes = SmallModulus::GetPrimes(40, 5, 8192);
    parms.set_coeff_modulus(primes);
    parms.set_plain_modulus(1 << 20);

    /*
    Create the context that has a chain of encryption parameters.
    */
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    When SEALContext is created from a given EncryptionParameters instance,
    Microsoft SEAL automatically creates a so-called "modulus switching chain",
    which is a chain of other encryption parameters derived from the original set.
    The parameters in the modulus switching chain are the same as the original
    parameters with the exception that size of the coefficient modulus is
    decreasing going down the chain. More precisely, each parameter set in the
    chain attempts to remove the last coefficient modulus prime from the
    previous set; this continues until the parameter set is no longer valid
    (e.g. plain_modulus is larger than the remaining coeff_modulus). It is easy
    to walk through the chain and access all the parameter sets. Additionally,
    each parameter set in the chain has a `chain_index' that indicates its
    position in the chain so that the last set has index 0. We say that a set
    of encryption parameters, or an object carrying those encryption parameters,
    is at a higher level in the chain than another set of parameters if its the
    chain index is bigger, i.e. it is earlier in the chain.

    The chain starts with 'key_context_data()' that has the full list of primes.
    This intance of EncryptionParameters (including the last prime) are reserved
    for key generation and noise reduction in Microsoft SEAL.
    Ciphertexts, plaintexts, and evaluation start with the next in chain
    accessible via 'first_context_data()'.
    */
    cout << "Printing the modulus switching chain:" << endl;

    auto context_data = context->key_context_data();
    cout << "----- Level (chain index): " << context_data->chain_index();
    cout << " ...... key_context_data()" << endl;
    cout << "\tparms_id: " << context_data->parms_id() << endl;
    cout << "\tcoeff_modulus primes: ";
    cout << hex;
    for(const auto &prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << dec << endl;
    cout << "\\" << endl;
    cout << " \\-->";

    size_t level = context_data->parms().coeff_modulus().size() - 1;
    for(context_data = context->first_context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index();
        if (context_data == context->first_context_data())
        {
            cout << " ...... first_context_data()" << endl;
        }
        else if (context_data == context->last_context_data())
        {
            cout << " ...... last_context_data()" << endl;
        }
        else
        {
            cout << endl;
        }        
        cout << "\tparms_id: " << context_data->parms_id() << endl;
        cout << "\tcoeff_modulus primes: ";
        cout << hex;
        for(const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->";
    }
    cout << " End of chain reached" << endl << endl;

    /*
    To demonstrate that a particular set of encryption parameters is identified
    uniquely by a hash 'parms_id'. We manually removes the last prime and create
    a new set of encryption parameters that are the same with the encryption
    parameters in 'context->first_context_data()'.
    */
    cout << "Create a new context with new encryption parameters" << endl;
    primes.pop_back();
    parms.set_coeff_modulus(primes);
    auto context2 = SEALContext::Create(parms);
    cout << "-- 'first_context_data' in previous context: " << endl;
    context_data = context->first_context_data();
    cout << "\tchain index: " << context_data->chain_index() << endl;
    cout << "\tparms_id: " << context_data->parms_id() << endl;
    cout << "\tcoeff_modulus primes: ";
    cout << hex;
    for(const auto &prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << endl << "-- 'key_context_data' in this context: " << endl;
    context_data = context2->key_context_data();
    cout << "\tchain index: " << context_data->chain_index() << endl;
    cout << "\tparms_id: " << context_data->parms_id() << endl;
    cout << "\tcoeff_modulus primes: ";
    cout << hex;
    for(const auto &prime : context_data->parms().coeff_modulus())
    {
        cout << prime.value() << " ";
    }
    cout << endl << "They are identical." << endl << endl << endl;

    /*
    All keys and ciphertext, and in the CKKS also plaintexts, carry the parms_id
    for the encryption parameters they are created with, allowing Microsoft SEAL
    to quickly determine whether the objects are valid for use and compatible
    for homomorphic computations. Microsoft SEAL takes care of managing, and
    verifying the parms_id for all objects so the user should have no reason to
    change it by hand.
    */
    cout << "Refer to the printed modulus switching chain: " << endl;
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    auto galois_keys = keygen.galois_keys();
    cout << "-- parms_id of public_key:  " << public_key.parms_id() << endl;
    cout << "-- parms_id of secret_key:  " << secret_key.parms_id() << endl;
    cout << "-- parms_id of relin_keys:  " << relin_keys.parms_id() << endl;
    cout << "-- parms_id of galois_keys: " << galois_keys.parms_id() << endl;


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
    cout << "-- parms_id of plain: " << plain.parms_id() << " (not set)" << endl;
    cout << "-- parms_id of encrypted:   " << encrypted.parms_id() << endl << endl;

    cout << "Keys are at at a higher level than ciphertexts." << endl << endl;

    /*
    Modulus switching changes the ciphertext parameters to any set down the
    chain from the current one. The function mod_switch_to_next(...) always
    switches to the next set down the chain, whereas mod_switch_to(...) switches
    to a parameter set down the chain corresponding to a given parms_id.
    */
    cout << "Effects of modulus switching: " << endl;
    context_data = context->first_context_data();
    cout << "-----";
    while(context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
        cout << "\tparms_id of encrypted: " << encrypted.parms_id() << endl;
        cout << "\tNoise budget at this level: "
            << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
        cout << "\\" << endl;
        cout << " \\-->";
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }
    cout << " Level (chain index): " << context_data->chain_index() << endl;
    cout << "\tparms_id of encrypted: " << encrypted.parms_id() << endl;
    cout << "\tNoise budget at this level: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "\\" << endl;
    cout << " \\-->";
    cout << " End of chain reached" << endl << endl;

    /*
    At this point it is hard to see any benefit in doing this: we lost a huge
    amount of noise budget (i.e. computational power) at each switch and seemed
    to get nothing in return. Decryption still works.
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
    right, as we will see below.
    
    First we recreate the original ciphertext (with the largest parameters) and
    perform some simple computations on it.
    */
    cout << "More efficient computation with moudlus switching: " << endl;
    encryptor.encrypt(plain, encrypted);
    cout << "\tNoise budget before squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    cout << "\tNoise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    From the print-out we see that the noise budget after these computations is
    just slightly below the level we would have in a fresh ciphertext after one
    modulus switch (135 bits). Surprisingly, in this case modulus switching has
    no effect at all on the noise budget.
    */
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "\tNoise budget after modulus switching: "
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
    cout << "\tNoise budget after squaring: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    evaluator.mod_switch_to_next_inplace(encrypted);
    cout << "\tNoise budget after modulus switching: "
        << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;

    /*
    At this point the ciphertext still decrypts correctly, has very small size,
    and the computation was as efficient as possible. Note that the decryptor
    can be used to decrypt a ciphertext at any level in the modulus switching
    chain as long as the secret key is at a higher level in the same chain.
    */
    decryptor.decrypt(encrypted, plain);
    cout << "Decryption of fourth power: " << endl;
    cout << "\t" << plain.to_string() << endl << endl;

    /*
    In BFV modulus switching is not necessary and in some cases the user might
    not want to create the modulus switching chain, except for the highest two
    levels. This can be done by passing a bool `false' to the
    SEALContext::Create(...) function as follows.
    */
    context = SEALContext::Create(parms, false);

    /*
    We can check that indeed the modulus switching chain has been created only
    for the highest two levels (keys and fresh ciphertexts).
    The following loop should execute only once.
    */
    cout << "-----";
    for (context_data = context->key_context_data(); context_data;
        context_data = context_data->next_context_data())
    {
        cout << " Level (chain index): " << context_data->chain_index() << endl;
        cout << "\tparms_id: " << context_data->parms_id() << endl;
        cout << "\tcoeff_modulus primes: ";
        cout << hex;
        for (const auto &prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << dec << endl;
        cout << "\\" << endl;
        cout << " \\-->";
    }
    cout << " End of chain reached" << endl << endl;

    /*
    It is very important to understand how this example works since in the CKKS
    scheme modulus switching has a much more fundamental purpose and the next
    examples will be difficult to understand unless these basic properties are
    totally clear.
    */
}
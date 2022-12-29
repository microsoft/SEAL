// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bgv_basics()
{
    print_example_banner("Example: BGV Basics");

    /*
    As an example, we evaluate the degree 8 polynomial

        x^8

    over an encrypted x over integers 1, 2, 3, 4. The coefficients of the
    polynomial can be considered as plaintext inputs, as we will see below. The
    computation is done modulo the plain_modulus 1032193.

    Computing over encrypted data in the BGV scheme is similar to that in BFV.
    The purpose of this example is mainly to explain the differences between BFV
    and BGV in terms of ciphertext coefficient modulus selection and noise control.

    Most of the following code are repeated from "BFV basics" and "encoders" examples.
    */

    /*
    Note that scheme_type is now "bgv".
    */
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    We can certainly use BFVDefault coeff_modulus. In later parts of this example,
    we will demonstrate how to choose coeff_modulus that is more useful in BGV.
    */
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);

    /*
    Print the parameters that we have chosen.
    */
    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    /*
    Batching and slot operations are the same in BFV and BGV.
    */
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /*
    Here we create the following matrix:
        [ 1,  2,  3,  4,  0,  0, ...,  0 ]
        [ 0,  0,  0,  0,  0,  0, ...,  0 ]
    */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 1ULL;
    pod_matrix[1] = 2ULL;
    pod_matrix[2] = 3ULL;
    pod_matrix[3] = 4ULL;

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);
    Plaintext x_plain;
    cout << "Encode plaintext matrix to x_plain:" << endl;
    batch_encoder.encode(pod_matrix, x_plain);

    /*
    Next we encrypt the encoded plaintext.
    */
    Ciphertext x_encrypted;
    print_line(__LINE__);
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;
    cout << endl;

    /*
    Then we compute x^2.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    cout << "    + size of x_squared: " << x_squared.size() << endl;
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "    + size of x_squared (after relinearization): " << x_squared.size() << endl;
    cout << "    + noise budget in x_squared: " << decryptor.invariant_noise_budget(x_squared) << " bits" << endl;
    Plaintext decrypted_result;
    decryptor.decrypt(x_squared, decrypted_result);
    vector<uint64_t> pod_result;
    batch_encoder.decode(decrypted_result, pod_result);
    cout << "    + result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    /*
    Next we compute x^4.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_4th (x^4)," << endl;
    Ciphertext x_4th;
    evaluator.square(x_squared, x_4th);
    cout << "    + size of x_4th: " << x_4th.size() << endl;
    evaluator.relinearize_inplace(x_4th, relin_keys);
    cout << "    + size of x_4th (after relinearization): " << x_4th.size() << endl;
    cout << "    + noise budget in x_4th: " << decryptor.invariant_noise_budget(x_4th) << " bits" << endl;
    decryptor.decrypt(x_4th, decrypted_result);
    batch_encoder.decode(decrypted_result, pod_result);
    cout << "    + result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    /*
    Last we compute x^8. We run out of noise budget.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_8th (x^8)," << endl;
    Ciphertext x_8th;
    evaluator.square(x_4th, x_8th);
    cout << "    + size of x_8th: " << x_8th.size() << endl;
    evaluator.relinearize_inplace(x_8th, relin_keys);
    cout << "    + size of x_8th (after relinearization): " << x_8th.size() << endl;
    cout << "    + noise budget in x_8th: " << decryptor.invariant_noise_budget(x_8th) << " bits" << endl;
    cout << "NOTE: Decryption can be incorrect if noise budget is zero." << endl;

    cout << endl;
    cout << "~~~~~~ Use modulus switching to calculate x^8 ~~~~~~" << endl;

    /*
    Noise budget has reached 0, which means that decryption cannot be expected
    to give the correct result. BGV requires modulus switching to reduce noise
    growth. In the following demonstration, we will insert a modulus switching
    after each relinearization.
    */
    print_line(__LINE__);
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;
    cout << endl;

    /*
    Then we compute x^2.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    cout << "    + noise budget in x_squared (previously): " << decryptor.invariant_noise_budget(x_squared) << " bits"
         << endl;
    evaluator.square(x_encrypted, x_squared);
    evaluator.relinearize_inplace(x_squared, relin_keys);
    evaluator.mod_switch_to_next_inplace(x_squared);
    cout << "    + noise budget in x_squared (with modulus switching): " << decryptor.invariant_noise_budget(x_squared)
         << " bits" << endl;
    decryptor.decrypt(x_squared, decrypted_result);
    batch_encoder.decode(decrypted_result, pod_result);
    cout << "    + result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    /*
    Next we compute x^4.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_4th (x^4)," << endl;
    cout << "    + noise budget in x_4th (previously): " << decryptor.invariant_noise_budget(x_4th) << " bits" << endl;
    evaluator.square(x_squared, x_4th);
    evaluator.relinearize_inplace(x_4th, relin_keys);
    evaluator.mod_switch_to_next_inplace(x_4th);
    cout << "    + noise budget in x_4th (with modulus switching): " << decryptor.invariant_noise_budget(x_4th)
         << " bits" << endl;
    decryptor.decrypt(x_4th, decrypted_result);
    batch_encoder.decode(decrypted_result, pod_result);
    cout << "    + result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    /*
    Last we compute x^8. We still have budget left.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_8th (x^8)," << endl;
    cout << "    + noise budget in x_8th (previously): " << decryptor.invariant_noise_budget(x_8th) << " bits" << endl;
    evaluator.square(x_4th, x_8th);
    evaluator.relinearize_inplace(x_8th, relin_keys);
    evaluator.mod_switch_to_next_inplace(x_8th);
    cout << "    + noise budget in x_8th (with modulus switching): " << decryptor.invariant_noise_budget(x_8th)
         << " bits" << endl;
    decryptor.decrypt(x_8th, decrypted_result);
    batch_encoder.decode(decrypted_result, pod_result);
    cout << "    + result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);

    /*
    Although with modulus switching x_squared has less noise budget than before,
    noise budget is consumed at a slower rate. To achieve the optimal consumption
    rate of noise budget in an application, one needs to carefully choose the
    location to insert modulus switching and manually choose coeff_modulus.
    */
}

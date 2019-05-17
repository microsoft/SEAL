// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_rotation_bfv()
{
    print_example_banner("Rotation BFV");

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Default(8192));
    parms.set_plain_modulus(65537);
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

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
    First we use BatchEncoder to compose the matrix into a plaintext.
    Next we encrypt the plaintext as usual.
    */
    Plaintext plain_matrix;
    cout << "-- Encoding and encrypting: ";
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "Done" << endl;
    cout << "\tNoise budget in fresh encryption: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    cout << endl;

    /*
    Rotation requires galois keys.
    */
    GaloisKeys gal_keys = keygen.galois_keys();

    /*
    Now rotate the rows to the left 3 steps, decrypt, decode, and print.
    */
    cout << "-- Rotating rows 3 steps left: ";
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, gal_keys);
    cout << "Done" << endl;
    Plaintext plain_result;
    cout << "\tNoise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    cout << "   Decrypting and decoding: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    cout << "Done" << endl;
    print_matrix(pod_matrix, row_size);
    cout << endl;

    /*
    Rotate columns (swap rows), decrypt, decode, and print.
    */
    cout << "-- Rotating columns: ";
    evaluator.rotate_columns_inplace(encrypted_matrix, gal_keys);
    cout << "Done" << endl;
    cout << "\tNoise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    cout << endl;
    cout << "   Decrypting and decoding: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    cout << "Done" << endl;
    print_matrix(pod_matrix, row_size);
    cout << endl;

    /*
    Rotate rows to the right 4 steps, decrypt, decode, and print.
    */
    cout << "-- Rotating rows 4 steps right: " << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, gal_keys);
    cout << "Done" << endl;
    cout << "\tNoise budget after rotation: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;
    cout << "   Decrypting and decoding: ";
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    cout << "Done" << endl;
    print_matrix(pod_matrix, row_size);

    /*
    We can see that rotation does not consume noise budget.
    This is the benefit of using an extra coeff_modulus which is explained in
    example `levels`. We can briefly demonstrate the effect of wrongly setting
    EncryptionParameters.

    If the last prime passed to coeff_modulus is smaller than other primes,
    rotation and relinearization will introduce noise.
    We replace the last two primes to ensure coefficient modulus has the same
    size as before.
    */
    cout << "Resetting primes in encryption parameters" << endl;
    auto coeff_modulus = context->key_context_data()->parms().coeff_modulus();
    coeff_modulus.pop_back();
    coeff_modulus.pop_back();
    coeff_modulus.push_back(SmallModulus::GetPrimes(60, 1, 8192)[0]);
    coeff_modulus.push_back(SmallModulus::GetPrimes(28, 1, 8192)[0]);
    parms.set_coeff_modulus(coeff_modulus);
    context = SEALContext::Create(parms);
    print_parameters(context);

    /*
    Every step is the same.
    */
    KeyGenerator keygen2(context);
    public_key = keygen2.public_key();
    secret_key = keygen2.secret_key();
    relin_keys = keygen2.relin_keys();
    Encryptor encryptor2(context, public_key);
    Evaluator evaluator2(context);
    Decryptor decryptor2(context, secret_key);
    BatchEncoder batch_encoder2(context);
    gal_keys = keygen2.galois_keys();

    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    batch_encoder2.encode(pod_matrix, plain_matrix);
    encryptor2.encrypt(plain_matrix, encrypted_matrix);
    cout << "-- Rotating rows 3 steps left: ";
    evaluator2.rotate_rows_inplace(encrypted_matrix, 3, gal_keys);
    cout << "Done" << endl;
    cout << "\tNoise budget after rotation: "
        << decryptor2.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /*
    We can see now there is a significant noise growth introduced in rotation.
    It is similar in relinearization.
    */
}

void example_rotation_ckks()
{
    print_example_banner("Rotation CKKS");

    /*
    We show how to apply vector rotations on the encrypted data. This is very
    similar to how matrix rotations work in the BFV scheme.
    */
    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    auto context = SEALContext::Create(parms);
    print_parameters(context);

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys = keygen.relin_keys();
    GaloisKeys gal_keys = keygen.galois_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
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

    /*
    Choosing the scale will be explained in example_basic_ckks.
    */
    auto scale = pow(2.0, 50);

    cout << "-- Encoding and encrypting: ";
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    cout << "Done" << endl;

    Ciphertext rotated;
    cout << "-- Rotating 2 steps left: ";
    evaluator.rotate_vector(encrypted, 2, gal_keys, rotated);
    cout << "Done" << endl;
    cout << "   Decrypting and decoding: ";
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    ckks_encoder.decode(plain, result);
    cout << "Done" << endl;
    print_vector(result, 3, 7);
}

void example_rotation()
{
    print_example_banner("Example: Rotation");

    example_rotation_bfv();

    example_rotation_ckks();
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

/*
Both the BFV scheme (with BatchEncoder) as well as the CKKS scheme support native
vectorized computations on encrypted numbers. In addition to computing slot-wise,
it is possible to rotate the encrypted vectors cyclically.
*/
void example_rotation_bfv()
{
    print_example_banner("Rotation BFV");

    EncryptionParameters parms(scheme_type::BFV);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

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
    First we use BatchEncoder to encode the matrix into a plaintext. We encrypt
    the plaintext as usual.
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
    Rotations require yet another type of special key called `Galois keys'. These
    are easily obtained from the KeyGenerator.
    */
    GaloisKeys gal_keys = keygen.galois_keys();

    /*
    Now rotate both matrix rows 3 steps to the left, decrypt, decode, and print.
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
    We can also rotate the columns, i.e., swap the rows.
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
    Finally, we rotate the rows 4 steps to the right, decrypt, decode, and print.
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
    Note that rotations do not consume any noise budget. However, this is only
    the case when the special prime is at least as large as the other primes. The
    same holds for relinearization. Microsoft SEAL does not require that the
    special prime is of any particular size, so ensuring this is the case is left
    for the user to do.
    */
}

void example_rotation_ckks()
{
    print_example_banner("Rotation CKKS");

    /*
    Rotations in the CKKS scheme work very similarly to rotations in BFV.
    */
    EncryptionParameters parms(scheme_type::CKKS);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 40, 40, 40, 40, 40 }));

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

    /*
    With the CKKS scheme it is also possible to evaluate a complex conjugation on
    a vector of encrypted complex numbers, using Evaluator::complex_conjugate.
    This is in fact a kind of rotation, and requires also Galois keys.
    */
}

void example_rotation()
{
    print_example_banner("Example: Rotation");

    /*
    Run all rotation examples.
    */
    example_rotation_bfv();
    example_rotation_ckks();
}
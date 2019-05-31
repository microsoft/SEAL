// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void bfv_performance_test(shared_ptr<SEALContext> context)
{
    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context->first_context_data()->parms();
    auto &plain_modulus = parms.plain_modulus();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context->using_keyswitching())
    {
        /*
        Generate relinearization keys.
        */
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        relin_keys = keygen.relin_keys();
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context->key_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        /*
        Generate Galois keys. In larger examples the Galois keys can use a lot of
        memory, which can be a problem in constrained systems. The user should
        try some of the larger runs of the test and observe their effect on the
        memory pool allocation size. The key generation can also take a long time,
        as can be observed from the print-out.
        */
        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        gal_keys = keygen.galois_keys();
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
    size_t slot_count = batch_encoder.slot_count();
    vector<uint64_t> pod_vector;
    random_device rd;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_vector.push_back(rd() % plain_modulus.value());
    }

    cout << "Running tests ";
    for (int i = 0; i < count; i++)
    {
        /*
        [Batching]
        There is nothing unusual here. We batch our random plaintext matrix
        into the polynomial. Note how the plaintext we create is of the exactly
        right size so unnecessary reallocations are avoided.
        */
        Plaintext plain(parms.poly_modulus_degree(), 0);
        time_start = chrono::high_resolution_clock::now();
        batch_encoder.encode(pod_vector, plain);
        time_end = chrono::high_resolution_clock::now();
        time_batch_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        /*
        [Unbatching]
        We unbatch what we just batched.
        */
        vector<uint64_t> pod_vector2(slot_count);
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
        We make sure our ciphertext is already allocated and large enough
        to hold the encryption with these encryption parameters. We encrypt
        our random batched matrix here.
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
        We create two ciphertexts and perform a few additions with them.
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
            chrono::microseconds>(time_end - time_start);

        /*
        [Multiply]
        We multiply two ciphertexts. Since the size of the result will be 3,
        and will overwrite the first argument, we reserve first enough memory
        to avoid reallocating during multiplication.
        */
        encrypted1.reserve(3);
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_inplace(encrypted1, encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        /*
        [Multiply Plain]
        We multiply a ciphertext with a random plaintext. Recall that
        multiply_plain does not change the size of the ciphertext so we use
        encrypted2 here.
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.multiply_plain_inplace(encrypted2, plain);
        time_end = chrono::high_resolution_clock::now();
        time_multiply_plain_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        /*
        [Square]
        We continue to use encrypted2. Now we square it; this should be
        faster than generic homomorphic multiplication.
        */
        time_start = chrono::high_resolution_clock::now();
        evaluator.square_inplace(encrypted2);
        time_end = chrono::high_resolution_clock::now();
        time_square_sum += chrono::duration_cast<
            chrono::microseconds>(time_end - time_start);

        if (context->using_keyswitching())
        {
            /*
            [Relinearize]
            Time to get back to encrypted1. We now relinearize it back
            to size 2. Since the allocation is currently big enough to
            contain a ciphertext of size 3, no costly reallocations are
            needed in the process.
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
                chrono::microseconds>(time_end - time_start);;

            /*
            [Rotate Rows Random]
            We rotate matrix rows by a random number of steps. This is much more
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
        }

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
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rotate_rows_one_step = time_rotate_rows_one_step_sum.count() / (2 * count);
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
    if (context->using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rotate rows one step: " << avg_rotate_rows_one_step <<
            " microseconds" << endl;
        cout << "Average rotate rows random: " << avg_rotate_rows_random <<
            " microseconds" << endl;
        cout << "Average rotate columns: " << avg_rotate_columns <<
            " microseconds" << endl;
    }
    cout.flush();
}

void ckks_performance_test(shared_ptr<SEALContext> context)
{
    chrono::high_resolution_clock::time_point time_start, time_end;

    print_parameters(context);
    cout << endl;

    auto &parms = context->first_context_data()->parms();
    size_t poly_modulus_degree = parms.poly_modulus_degree();

    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    cout << "Done" << endl;

    auto secret_key = keygen.secret_key();
    auto public_key = keygen.public_key();

    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    chrono::microseconds time_diff;
    if (context->using_keyswitching())
    {
        cout << "Generating relinearization keys: ";
        time_start = chrono::high_resolution_clock::now();
        relin_keys = keygen.relin_keys();
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;

        if (!context->first_context_data()->qualifiers().using_batching)
        {
            cout << "Given encryption parameters do not support batching." << endl;
            return;
        }

        cout << "Generating Galois keys: ";
        time_start = chrono::high_resolution_clock::now();
        gal_keys = keygen.galois_keys();
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
        cout << "Done [" << time_diff.count() << " microseconds]" << endl;
    }

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
        For scale we use the square root of the last coeff_modulus prime
        from parms.
        */
        Plaintext plain(parms.poly_modulus_degree() *
            parms.coeff_modulus().size(), 0);
        /*

        */
        double scale = sqrt(static_cast<double>(
            parms.coeff_modulus().back().value()));
        time_start = chrono::high_resolution_clock::now();
        ckks_encoder.encode(pod_vector, scale, plain);
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
            chrono::microseconds>(time_end - time_start);

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

        if (context->using_keyswitching())
        {
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
                chrono::microseconds>(time_end - time_start);

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
        }

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
    auto avg_add = time_add_sum.count() / (3 * count);
    auto avg_multiply = time_multiply_sum.count() / count;
    auto avg_multiply_plain = time_multiply_plain_sum.count() / count;
    auto avg_square = time_square_sum.count() / count;
    auto avg_relinearize = time_relinearize_sum.count() / count;
    auto avg_rescale = time_rescale_sum.count() / count;
    auto avg_rotate_one_step = time_rotate_one_step_sum.count() / (2 * count);
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
    if (context->using_keyswitching())
    {
        cout << "Average relinearize: " << avg_relinearize << " microseconds" << endl;
        cout << "Average rescale: " << avg_rescale << " microseconds" << endl;
        cout << "Average rotate vector one step: " << avg_rotate_one_step <<
            " microseconds" << endl;
        cout << "Average rotate vector random: " << avg_rotate_random << " microseconds" << endl;
        cout << "Average complex conjugate: " << avg_conjugate << " microseconds" << endl;
    }
    cout.flush();
}

void example_bfv_performance_default()
{
    print_example_banner("BFV Performance Test with Degrees: 4096, 8192, and 16384");

    EncryptionParameters parms(scheme_type::BFV);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(786433);
    bfv_performance_test(SEALContext::Create(parms));

    cout << endl;
    poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(786433);
    bfv_performance_test(SEALContext::Create(parms));

    cout << endl;
    poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(786433);
    bfv_performance_test(SEALContext::Create(parms));

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // poly_modulus_degree = 32768;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // parms.set_plain_modulus(786433);
    // bfv_performance_test(SEALContext::Create(parms));
}

void example_bfv_performance_custom()
{
    size_t poly_modulus_degree = 0;
    cout << endl << "Set poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ";
    if (!(cin >> poly_modulus_degree))
    {
        cout << "Invalid option." << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        return;
    }
    if (poly_modulus_degree < 1024 || poly_modulus_degree > 32768 ||
        (poly_modulus_degree & (poly_modulus_degree - 1)) != 0)
    {
        cout << "Invalid option." << endl;
        return;
    }

    string banner = "BFV Performance Test with Degree: ";
    print_example_banner(banner + to_string(poly_modulus_degree));

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    if (poly_modulus_degree == 1024)
    {
        parms.set_plain_modulus(12289);
    }
    else
    {
        parms.set_plain_modulus(786433);
    }
    bfv_performance_test(SEALContext::Create(parms));
}

void example_ckks_performance_default()
{
    print_example_banner("CKKS Performance Test with Degrees: 4096, 8192, and 16384");

    // It is not recommended to use BFVDefault primes in CKKS. However, for performance
    // test, BFVDefault primes are good enough.
    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_performance_test(SEALContext::Create(parms));

    cout << endl;
    poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_performance_test(SEALContext::Create(parms));

    cout << endl;
    poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_performance_test(SEALContext::Create(parms));

    /*
    Comment out the following to run the biggest example.
    */
    // cout << endl;
    // poly_modulus_degree = 32768;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    // ckks_performance_test(SEALContext::Create(parms));
}

void example_ckks_performance_custom()
{
    size_t poly_modulus_degree = 0;
    cout << endl << "Set poly_modulus_degree (1024, 2048, 4096, 8192, 16384, or 32768): ";
    if (!(cin >> poly_modulus_degree))
    {
        cout << "Invalid option." << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        return;
    }
    if (poly_modulus_degree < 1024 || poly_modulus_degree > 32768 ||
        (poly_modulus_degree & (poly_modulus_degree - 1)) != 0)
    {
        cout << "Invalid option." << endl;
        return;
    }

    string banner = "CKKS Performance Test with Degree: ";
    print_example_banner(banner + to_string(poly_modulus_degree));

    EncryptionParameters parms(scheme_type::CKKS);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    ckks_performance_test(SEALContext::Create(parms));
}

/*
Prints a sub-menu to select the performance test.
*/
void example_performance_test()
{
    print_example_banner("Example: Performance Test");

    while (true)
    {
        cout << endl;
        cout << "Select a scheme (and optionally poly_modulus_degree):" << endl;
        cout << "  1. BFV with default degrees" << endl;
        cout << "  2. BFV with a custom degree" << endl;
        cout << "  3. CKKS with default degrees" << endl;
        cout << "  4. CKKS with a custom degree" << endl;
        cout << "  0. Back to main menu" << endl;

        int selection = 0;
        cout << endl << "> Run performance test (1 ~ 4) or go back (0): ";
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
            example_bfv_performance_default();
            break;

        case 2:
            example_bfv_performance_custom();
            break;

        case 3:
            example_ckks_performance_default();
            break;

        case 4:
            example_ckks_performance_custom();
            break;

        case 0:
            cout << endl;
            return;

        default:
            cout << "Invalid option." << endl;
        }
    }
}
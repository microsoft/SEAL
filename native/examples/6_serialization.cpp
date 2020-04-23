// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

/*
In this example we show how serialization works in Microsoft SEAL. Specifically,
we present important concepts that enable the user to optimize the data size when
communicating ciphertexts and keys for outsourced computation. Unlike the previous
examples, we organize this one in a client-server style for maximal clarity. The
server selects encryption parameters, the client generates keys, the server does
the encrypted computation, and the client decrypts.
*/
void example_serialization()
{
    print_example_banner("Example: Serialization");

    /*
    We require ZLIB support for this example to be available.
    */
#ifndef SEAL_USE_ZLIB
    cout << "ZLIB support is not enabled; this example is not available." << endl;
    cout << endl;
    return;
#else
    /*
    To simulate client-server interaction, we set up a shared C++ stream. In real
    use-cases this can be a network buffer, a filestream, or any shared resource.

    It is critical to note that all data serialized by Microsoft SEAL is in binary
    form, so it is not meaningful to print the data as ASCII characters. Encodings
    such as Base64 would increase the data size, which is already a bottleneck in
    homomorphic encryption. Hence, serialization into text is not supported or
    recommended.

    We feel it is important to remind users that filestream serialization will
    always require the ios::binary flag to signal that the serialized data is
    binary data and not text. For example, an appropriate output filestream could
    be set up as:

        ofstream ofs("filename", ios::binary);

    In this example we use an std::stringstream, where the ios::binary flag is
    not needed. Note that the default constructor of std::stringstream opens the
    stream with ios::in | ios::out so both reading and writing will be possible.
    */
    stringstream parms_stream;
    stringstream data_stream;
    stringstream sk_stream;

    /*
    The server first determines the computation and sets encryption parameters
    accordingly.
    */
    {
        EncryptionParameters parms(scheme_type::CKKS);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 20, 50 }));

        /*
        Serialization of the encryption parameters to our shared stream is very
        simple with the EncryptionParameters::save function.
        */
        auto size = parms.save(parms_stream);

        /*
        The return value of this function is the actual byte count of data written
        to the stream.
        */
        print_line(__LINE__);
        cout << "EncryptionParameters: wrote " << size << " bytes" << endl;

        /*
        Before moving on, we will take some time to discuss further options in
        serialization. These will become particularly important when the user
        needs to optimize communication and storage sizes.
        */

        /*
        It is possible to enable or disable ZLIB ("deflate") compression for
        serialization by providing EncryptionParameters::save with the desired
        compression mode as in the following examples:

            auto size = parms.save(shared_stream, compr_mode_type::none);
            auto size = parms.save(shared_stream, compr_mode_type::deflate);

        If Microsoft SEAL is compiled with ZLIB support, the default is to use
        compr_mode_type::deflate, so to instead disable compression one would use
        the first version of the two.
        */

        /*
        It is also possible to serialize data directly to a buffer. For this, one
        needs to know an upper bound for the required buffer size, which can be
        obtained using the EncryptionParameters::save_size function. This function
        also accepts the desired compression mode, with compr_mode_type::deflate
        being the default when Microsoft SEAL is compiled with ZLIB support.

        In more detail, the output of EncryptionParameters::save_size is as follows:

            - Exact buffer size required for compr_mode_type::none;
            - Upper bound on the size required for compr_mode_type::deflate.

        As we can see from the print-out, the sizes returned by these functions
        are significantly larger than the compressed size written into the shared
        stream in the beginning. This is normal: compression yielded a significant
        improvement in the data size, yet it is hard to estimate the size of the
        compressed data.
        */
        print_line(__LINE__);
        cout << "EncryptionParameters: data size upper bound (compr_mode_type::none): "
             << parms.save_size(compr_mode_type::none) << endl;
        cout << "             "
             << "EncryptionParameters: data size upper bound (compr_mode_type::deflate): "
             << parms.save_size(compr_mode_type::deflate) << endl;

        /*
        As an example, we now serialize the encryption parameters to a fixed size
        buffer.
        */
        vector<SEAL_BYTE> byte_buffer(static_cast<size_t>(parms.save_size()));
        parms.save(reinterpret_cast<SEAL_BYTE *>(byte_buffer.data()), byte_buffer.size());

        /*
        To illustrate deserialization, we load back the encryption parameters
        from our buffer into another instance of EncryptionParameters. Note how
        EncryptionParameters::load in this case requires the size of the buffer,
        which is larger than the actual data size of the compressed parameters.
        The serialization format includes the true size of the data and the size
        of the buffer is only used for a sanity check.
        */
        EncryptionParameters parms2;
        parms2.load(reinterpret_cast<const SEAL_BYTE *>(byte_buffer.data()), byte_buffer.size());

        /*
        We can check that the saved and loaded encryption parameters indeed match.
        */
        print_line(__LINE__);
        cout << "EncryptionParameters: parms == parms2: " << boolalpha << (parms == parms2) << endl;

        /*
        The functions presented and used here exist for all Microsoft SEAL objects
        that are meaningful to serialize. However, it is important to understand
        more advanced techniques that can be used for further compressing the data
        size. We will present these techniques below.
        */
    }

    /*
    Client starts by loading the encryption parameters, sets up the SEALContext,
    and creates the required keys.
    */
    {
        EncryptionParameters parms;
        parms.load(parms_stream);

        /*
        Seek the parms_stream get head back to beginning of the stream because we
        will use the same stream to read the parameters repeatedly.
        */
        parms_stream.seekg(0, parms_stream.beg);

        auto context = SEALContext::Create(parms);

        KeyGenerator keygen(context);
        auto sk = keygen.secret_key();
        auto pk = keygen.public_key();

        /*
        We need to save the secret key so we can decrypt later.
        */
        sk.save(sk_stream);

        /*
        In this example we will also use relinearization keys. For realinearization
        and Galois keys the KeyGenerator::relin_keys and KeyGenerator::galois_keys
        functions return special Serializable<T> objects. These objects are meant
        to be serialized and never used locally. On the other hand, for local use
        of RelinKeys and GaloisKeys, the functions KeyGenerator::relin_keys_local
        and KeyGenerator::galois_keys_local can be used to create the RelinKeys
        and GaloisKeys objects directly. The difference is that the Serializable<T>
        objects contain a partly seeded version of the RelinKeys (or GaloisKeys)
        that will result in a significantly smaller size when serialized. Using
        this method has no impact on security. Such seeded RelinKeys (GaloisKeys)
        must be expanded before being used in computations; this is automatically
        done by deserialization.
        */
        Serializable<RelinKeys> rlk = keygen.relin_keys();

        /*
        Before continuing, we demonstrate the significant space saving from this
        method.
        */
        auto size_rlk = rlk.save(data_stream);

        RelinKeys rlk_local = keygen.relin_keys_local();
        auto size_rlk_local = rlk_local.save(data_stream);

        /*
        Now compare the serialized sizes of rlk and rlk_local.
        */
        print_line(__LINE__);
        cout << "Serializable<RelinKeys>: wrote " << size_rlk << " bytes" << endl;
        cout << "             "
             << "RelinKeys (local): wrote " << size_rlk_local << " bytes" << endl;

        /*
        Seek back in data_stream to where rlk data ended, i.e., size_rlk_local
        bytes backwards from current position.
        */
        data_stream.seekp(-size_rlk_local, data_stream.cur);

        /*
        Next set up the CKKSEncoder and Encryptor, and encrypt some numbers.
        */
        double scale = pow(2.0, 20);
        CKKSEncoder encoder(context);
        Plaintext plain1, plain2;
        encoder.encode(2.3, scale, plain1);
        encoder.encode(4.5, scale, plain2);

        Encryptor encryptor(context, pk);
        Ciphertext encrypted1, encrypted2;
        encryptor.encrypt(plain1, encrypted1);
        encryptor.encrypt(plain2, encrypted2);

        /*
        Now, we could serialize both encrypted1 and encrypted2 to data_stream
        using Ciphertext::save. However, for this example, we demonstrate another
        size-saving trick that can come in handy.

        As you noticed, we set up the Encryptor using the public key. Clearly this
        indicates that the CKKS scheme is a public-key encryption scheme. However,
        both BFV and CKKS can operate also in a symmetric-key mode. This can be
        beneficial when the public-key functionality is not exactly needed, like
        in simple outsourced computation scenarios. The benefit is that in these
        cases it is possible to produce ciphertexts that are partly seeded, hence
        significantly smaller. Such ciphertexts must be expanded before being used
        in computations; this is automatically done by deserialization.

        To use symmetric-key encryption, we need to set up the Encryptor with the
        secret key instead.
        */
        Encryptor sym_encryptor(context, sk);
        Serializable<Ciphertext> sym_encrypted1 = sym_encryptor.encrypt_symmetric(plain1);
        Serializable<Ciphertext> sym_encrypted2 = sym_encryptor.encrypt_symmetric(plain2);

        /*
        Before continuing, we demonstrate the significant space saving from this
        method.
        */
        auto size_sym_encrypted1 = sym_encrypted1.save(data_stream);
        auto size_encrypted1 = encrypted1.save(data_stream);

        /*
        Now compare the serialized sizes of encrypted1 and sym_encrypted1.
        */
        print_line(__LINE__);
        cout << "Serializable<Ciphertext> (symmetric-key): wrote " << size_sym_encrypted1 << " bytes" << endl;
        cout << "             "
             << "Ciphertext (public-key): wrote " << size_encrypted1 << " bytes" << endl;

        /*
        Seek back in data_stream to where sym_encrypted1 data ended, i.e.,
        size_encrypted1 bytes backwards from current position and write
        sym_encrypted2 right after sym_encrypted1.
        */
        data_stream.seekp(-size_encrypted1, data_stream.cur);
        sym_encrypted2.save(data_stream);

        /*
        We have seen how using KeyGenerator::relin_keys (KeyGenerator::galois_keys)
        can result in huge space savings over the local variants when the objects
        are not needed for local use. We have seen how symmetric-key encryption
        can be used to achieve much smaller ciphertext sizes when the public-key
        functionality is not needed.

        We would also like to draw attention to the fact there we could easily
        serialize multiple Microsoft SEAL objects sequentially in a stream. Each
        object writes its own size into the stream, so deserialization knows
        exactly how many bytes to read. We will see this working next.

        Finally, we would like to point out that none of these methods provide any
        space savings unless Microsoft SEAL is compiled with ZLIB support, or when
        serialized with compr_mode_type::none.
        */
    }

    /*
    The server can now compute on the encrypted data. We will recreate the
    SEALContext and set up an Evaluator here.
    */
    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        auto context = SEALContext::Create(parms);

        Evaluator evaluator(context);

        /*
        Next we need to load relinearization keys and the ciphertexts from our
        data_stream.
        */
        RelinKeys rlk;
        Ciphertext encrypted1, encrypted2;

        /*
        Deserialization is as easy as serialization.
        */
        rlk.load(context, data_stream);
        encrypted1.load(context, data_stream);
        encrypted2.load(context, data_stream);

        /*
        Compute the product, rescale, and relinearize.
        */
        Ciphertext encrypted_prod;
        evaluator.multiply(encrypted1, encrypted2, encrypted_prod);
        evaluator.relinearize_inplace(encrypted_prod, rlk);
        evaluator.rescale_to_next_inplace(encrypted_prod);

        /*
        We use data_stream to communicate encrypted_prod back to the client. There
        is no way to save the encrypted_prod as Serializable<Ciphertext> even
        though it is still a symmetric-key encryption: only freshly encrypted
        ciphertexts can be seeded. Note how the size of the result ciphertext is
        smaller than the size of a fresh ciphertext because it is at a lower level
        due to the rescale operation.
        */
        data_stream.seekp(0, parms_stream.beg);
        data_stream.seekg(0, parms_stream.beg);
        auto size_encrypted_prod = encrypted_prod.save(data_stream);

        print_line(__LINE__);
        cout << "Ciphertext (symmetric-key): wrote " << size_encrypted_prod << " bytes" << endl;
    }

    /*
    In the final step the client decrypts the result.
    */
    {
        EncryptionParameters parms;
        parms.load(parms_stream);
        parms_stream.seekg(0, parms_stream.beg);
        auto context = SEALContext::Create(parms);

        /*
        Load back the secret key from sk_stream.
        */
        SecretKey sk;
        sk.load(context, sk_stream);
        Decryptor decryptor(context, sk);
        CKKSEncoder encoder(context);

        Ciphertext encrypted_result;
        encrypted_result.load(context, data_stream);

        Plaintext plain_result;
        decryptor.decrypt(encrypted_result, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);

        print_line(__LINE__);
        cout << "Result: " << endl;
        print_vector(result, 3, 7);
    }

    /*
    Finally, we give a little bit more explanation of the structure of data
    serialized by Microsoft SEAL. Serialized data always starts with a 16-byte
    SEALHeader struct, as defined in native/src/seal/serialization.h, and is
    followed by the possibly compressed data for the object.

    A SEALHeader contains the following data:

        [offset 0] 2-byte magic number 0xA15E (Serialization::seal_magic)
        [offset 2] 1-byte indicating the header size in bytes (always 16)
        [offset 3] 1-byte indicating the Microsoft SEAL major version number
        [offset 4] 1-byte indicating the Microsoft SEAL minor version number
        [offset 5] 1-byte indicating the compression mode type
        [offset 6] 2-byte reserved field (unused)
        [offset 8] 8-byte size in bytes of the serialized data, including the header

    Currently Microsoft SEAL supports only little-endian systems.

    As an example, we demonstrate the SEALHeader created by saving a plaintext.
    Note that the SEALHeader is never compressed, so there is no need to specify
    the compression mode.
    */
    Plaintext pt("1x^2 + 3");
    stringstream stream;
    auto data_size = pt.save(stream);

    /*
    We can now load just the SEALHeader back from the stream as follows.
    */
    Serialization::SEALHeader header;
    Serialization::LoadHeader(stream, header);

    /*
    Now confirm that the size of data written to stream matches with what is
    indicated by the SEALHeader.
    */
    print_line(__LINE__);
    cout << "Size written to stream: " << data_size << " bytes" << endl;
    cout << "             "
         << "Size indicated in SEALHeader: " << header.size << " bytes" << endl;
    cout << endl;
#endif
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/encryptor.h"
#include "seal/keygenerator.h"
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    TEST(CiphertextTest, BFVCiphertextBasics)
    {
        EncryptionParameters parms(scheme_type::bfv);

        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus(CoeffModulus::Create(2, { 30 }));
        parms.set_plain_modulus(2);
        SEALContext context(parms, false, sec_level_type::none);

        Ciphertext ctxt(context);
        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        const uint64_t *ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ptr = ctxt.data();

        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(2);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(2ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());

        Ciphertext ctxt2{ ctxt };
        ASSERT_EQ(ctxt.coeff_modulus_size(), ctxt2.coeff_modulus_size());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt2.is_ntt_form());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt2.size());

        Ciphertext ctxt3;
        ctxt3 = ctxt;
        ASSERT_EQ(ctxt.coeff_modulus_size(), ctxt3.coeff_modulus_size());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt3.is_ntt_form());
        ASSERT_TRUE(ctxt.parms_id() == ctxt3.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt3.size());
    }

    TEST(CiphertextTest, BFVSaveLoadCiphertext)
    {
        stringstream stream;
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus(CoeffModulus::Create(2, { 30 }));
        parms.set_plain_modulus(2);

        SEALContext context(parms, false, sec_level_type::none);

        Ciphertext ctxt(context);
        Ciphertext ctxt2;
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ASSERT_FALSE(ctxt2.is_ntt_form());

        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(0xF0F0);
        context = SEALContext(parms, false);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        encryptor.encrypt(Plaintext("Ax^10 + 9x^9 + 8x^8 + 7x^7 + 6x^6 + 5x^5 + 4x^4 + 3x^3 + 2x^2 + 1"), ctxt);
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ASSERT_FALSE(ctxt2.is_ntt_form());
        ASSERT_TRUE(
            is_equal_uint(ctxt.data(), ctxt2.data(), parms.poly_modulus_degree() * parms.coeff_modulus().size() * 2));
        ASSERT_TRUE(ctxt.data() != ctxt2.data());
    }

    TEST(CiphertextTest, BFVBitPackSaveLoadCiphertext)
    {
        stringstream stream;
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(0xF0F0);

        SEALContext context(parms, false);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);

        Ciphertext ctxt;
        encryptor.encrypt(Plaintext("Ax^10 + 9x^9 + 8x^8 + 7x^7 + 6x^6 + 5x^5 + 4x^4 + 3x^3 + 2x^2 + 1"), ctxt);

        // A bit-packed round-trip preserves the ciphertext exactly
        auto bitpack_size = ctxt.save(stream, compr_mode_type::bitpack);
        Ciphertext ctxt2;
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_TRUE(
            is_equal_uint(ctxt.data(), ctxt2.data(), parms.poly_modulus_degree() * parms.coeff_modulus().size() * 2));
        ASSERT_TRUE(ctxt.data() != ctxt2.data());

        // The first block contains the ciphertext metadata (among it full-width parms_id hash words) and packs at
        // up to the full 64 bits, but every later block holds only coefficients smaller than the coefficient
        // modulus primes and hence packs at their bit width, so the total is guaranteed to beat the unpacked size.
        ASSERT_LT(bitpack_size, ctxt.save_size(compr_mode_type::none));

        // Seeded ciphertexts bit-pack too: the same seeded object saved with and without bit-packing must load to
        // identical data
        Encryptor sym_encryptor(context, keygen.secret_key());
        auto seeded = sym_encryptor.encrypt_symmetric(Plaintext("3x^7 + 2"));
        stringstream seeded_stream;
        seeded.save(seeded_stream, compr_mode_type::bitpack);
        seeded.save(seeded_stream, compr_mode_type::none);
        Ciphertext from_bitpack, from_none;
        from_bitpack.load(context, seeded_stream);
        from_none.load(context, seeded_stream);
        ASSERT_TRUE(from_bitpack.parms_id() == from_none.parms_id());
        ASSERT_TRUE(is_equal_uint(
            from_bitpack.data(), from_none.data(), parms.poly_modulus_degree() * parms.coeff_modulus().size() * 2));
    }

    TEST(CiphertextTest, LoadZeroSizeRejectsOversizedDynArray)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(257);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);

        Ciphertext ct;
        ct.resize(context, context.first_parms_id(), 0);
        ASSERT_EQ(0ULL, ct.size());

        stringstream ss;
        ct.save(ss, compr_mode_type::none);
        string blob = ss.str();

        // The DynArray element count is the final 8 bytes of a size-0 ciphertext.
        ASSERT_GE(blob.size(), sizeof(uint64_t));
        uint64_t evil = uint64_t(1) << 31;
        blob.replace(
            blob.size() - sizeof(uint64_t), sizeof(uint64_t),
            string(reinterpret_cast<const char *>(&evil), sizeof(uint64_t)));

        stringstream bad(blob);
        Ciphertext loaded;
        ASSERT_THROW(loaded.load(context, bad), logic_error);
    }

    TEST(CiphertextTest, LoadRejectsOversizedSeededCiphertext)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(256);
        parms.set_plain_modulus(257);
        parms.set_coeff_modulus(CoeffModulus::Create(256, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);
        Encryptor encryptor(context, keygen.secret_key());

        stringstream stream;
        encryptor.encrypt_symmetric(Plaintext("1")).save(stream, compr_mode_type::none);
        string blob = stream.str();

        constexpr size_t size_offset = sizeof(Serialization::SEALHeader) + sizeof(parms_id_type) + sizeof(seal_byte);
        ASSERT_GE(blob.size(), size_offset + sizeof(uint64_t));
        uint64_t invalid_size = 3;
        blob.replace(
            size_offset, sizeof(invalid_size),
            string(reinterpret_cast<const char *>(&invalid_size), sizeof(invalid_size)));

        stringstream bad(blob);
        Ciphertext loaded;
        ASSERT_THROW(loaded.load(context, bad), logic_error);
    }

    TEST(CiphertextTest, SaveTooSmallSeedMarkerNotTreatedAsSeed)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(8);
        parms.set_plain_modulus(257);
        parms.set_coeff_modulus(CoeffModulus::Create(8, { 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        ASSERT_TRUE(context.parameters_set());

        constexpr size_t poly_uint64_count = 8; // poly_modulus_degree * coeff_modulus_size
        constexpr size_t total = 2 * poly_uint64_count;

        Ciphertext ct;
        ct.resize(context, 2);
        ASSERT_EQ(2ULL, ct.size());
        ASSERT_EQ(total, ct.dyn_array().size());
        for (size_t i = 0; i < total; i++)
        {
            ct.data()[i] = i + 1;
        }
        ct.data(1)[0] = 0xFFFFFFFFFFFFFFFFULL;

        Ciphertext ct_plain;
        ct_plain.resize(context, 2);
        for (size_t i = 0; i < total; i++)
        {
            ct_plain.data()[i] = i + 1;
        }

        // The second polynomial is too small to hold a seed, so the marker word must
        // not select the seeded serialization; both save the full (unseeded) data.
        ASSERT_EQ(ct.save_size(compr_mode_type::none), ct_plain.save_size(compr_mode_type::none));

        stringstream ss;
        ct.save(ss, compr_mode_type::none);
        Ciphertext ct2;
        ct2.unsafe_load(context, ss);
        ASSERT_EQ(ct.size(), ct2.size());
        ASSERT_TRUE(is_equal_uint(ct.data(), ct2.data(), total));
        ASSERT_EQ(0xFFFFFFFFFFFFFFFFULL, ct2.data(1)[0]);
    }

    TEST(CiphertextTest, BGVCiphertextBasics)
    {
        EncryptionParameters parms(scheme_type::bgv);

        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus(CoeffModulus::Create(2, { 30 }));
        parms.set_plain_modulus(2);
        // auto context = SEALContext::Create(parms, false, sec_level_type::none);
        SEALContext context(parms, false, sec_level_type::none);

        Ciphertext ctxt(context);
        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        const uint64_t *ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ptr = ctxt.data();

        ctxt.reserve(10);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(10ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(2);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(2ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ptr = ctxt.data();

        ctxt.reserve(5);
        ASSERT_EQ(0ULL, ctxt.size());
        ASSERT_EQ(5ULL * 2 * 1, ctxt.dyn_array().capacity());
        ASSERT_EQ(0ULL, ctxt.dyn_array().size());
        ASSERT_EQ(2ULL, ctxt.poly_modulus_degree());
        ASSERT_TRUE(ptr != ctxt.data());
        ASSERT_TRUE(ctxt.parms_id() == context.first_parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());

        Ciphertext ctxt2{ ctxt };
        ASSERT_EQ(ctxt.coeff_modulus_size(), ctxt2.coeff_modulus_size());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt2.is_ntt_form());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt2.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt2.size());

        Ciphertext ctxt3;
        ctxt3 = ctxt;
        ASSERT_EQ(ctxt.coeff_modulus_size(), ctxt3.coeff_modulus_size());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.is_ntt_form(), ctxt3.is_ntt_form());
        ASSERT_TRUE(ctxt.parms_id() == ctxt3.parms_id());
        ASSERT_EQ(ctxt.poly_modulus_degree(), ctxt3.poly_modulus_degree());
        ASSERT_EQ(ctxt.size(), ctxt3.size());
    }

    TEST(CiphertextTest, BGVSaveLoadCiphertext)
    {
        stringstream stream;
        EncryptionParameters parms(scheme_type::bgv);
        parms.set_poly_modulus_degree(2);
        parms.set_coeff_modulus(CoeffModulus::Create(2, { 30 }));
        parms.set_plain_modulus(2);

        SEALContext context(parms, false, sec_level_type::none);

        Ciphertext ctxt(context);
        Ciphertext ctxt2;
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_FALSE(ctxt.is_ntt_form());
        ASSERT_FALSE(ctxt2.is_ntt_form());

        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(0xF0F0);
        context = SEALContext(parms, false);
        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);
        encryptor.encrypt(Plaintext("Ax^10 + 9x^9 + 8x^8 + 7x^7 + 6x^6 + 5x^5 + 4x^4 + 3x^3 + 2x^2 + 1"), ctxt);
        ctxt.save(stream);
        ctxt2.load(context, stream);
        ASSERT_TRUE(ctxt.parms_id() == ctxt2.parms_id());
        ASSERT_TRUE(ctxt.is_ntt_form());
        ASSERT_TRUE(ctxt2.is_ntt_form());
        ASSERT_TRUE(
            is_equal_uint(ctxt.data(), ctxt2.data(), parms.poly_modulus_degree() * parms.coeff_modulus().size() * 2));
        ASSERT_TRUE(ctxt.data() != ctxt2.data());
    }

    TEST(CiphertextTest, BGVLoadRejectsOutOfRangeCoeffBeforeNttConversion)
    {
        EncryptionParameters parms(scheme_type::bgv);
        parms.set_poly_modulus_degree(1024);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(1024));
        parms.set_plain_modulus(0xF0F0);
        SEALContext context(parms, false);

        KeyGenerator keygen(context);
        PublicKey pk;
        keygen.create_public_key(pk);
        Encryptor encryptor(context, pk);

        Ciphertext ct;
        encryptor.encrypt(Plaintext("1"), ct);
        ASSERT_TRUE(ct.is_ntt_form());

        // Relabel as coefficient form so load performs the BGV NTT conversion, and push one
        // coefficient out of [0, q) — a value the transform would otherwise launder.
        ct.is_ntt_form() = false;
        uint64_t q0 = context.get_context_data(ct.parms_id())->parms().coeff_modulus()[0].value();
        ct.data()[0] += q0;

        stringstream ss;
        ct.save(ss, compr_mode_type::none);

        Ciphertext loaded;
        ASSERT_THROW(loaded.load(context, ss), logic_error);
    }

} // namespace sealtest

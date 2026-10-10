// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/context.h"
#include "seal/galoiskeys.h"
#include "seal/keygenerator.h"
#include "seal/modulus.h"
#include "seal/relinkeys.h"
#include "seal/serialization.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace
    {
        // The compression modes available in this build
        vector<compr_mode_type> compressed_modes()
        {
            vector<compr_mode_type> modes;
#ifdef SEAL_USE_ZLIB
            modes.push_back(compr_mode_type::zlib);
#endif
#ifdef SEAL_USE_ZSTD
            modes.push_back(compr_mode_type::zstd);
#endif
            modes.push_back(compr_mode_type::bitpack);
            return modes;
        }

        // Key-switching keys with key_set_count key sets whose data is all zero
        KSwitchKeys make_zero_keys(const SEALContext &context, size_t key_set_count)
        {
            KSwitchKeys keys;
            keys.parms_id() = context.key_parms_id();
            keys.data().resize(key_set_count);
            for (auto &key_set : keys.data())
            {
                key_set.resize(context.first_context_data()->parms().coeff_modulus().size());
                for (auto &key : key_set)
                {
                    key.data().resize(context, context.key_parms_id(), 2);
                    key.data().is_ntt_form() = true;
                }
            }
            return keys;
        }
    } // namespace

    TEST(RelinKeysTest, RelinKeysSaveLoad)
    {
        auto relin_keys_save_load = [](scheme_type scheme) {
            stringstream stream;
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(64);
                parms.set_plain_modulus(1 << 6);
                parms.set_coeff_modulus(CoeffModulus::Create(64, { 60, 60 }));
                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                RelinKeys keys;
                RelinKeys test_keys;
                keygen.create_relin_keys(keys);
                keys.save(stream);
                test_keys.load(context, stream);
                ASSERT_EQ(keys.size(), test_keys.size());
                ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
                for (size_t j = 0; j < test_keys.size(); j++)
                {
                    for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                    {
                        ASSERT_EQ(keys.key(j + 2)[i].data().size(), test_keys.key(j + 2)[i].data().size());
                        ASSERT_EQ(
                            keys.key(j + 2)[i].data().dyn_array().size(),
                            test_keys.key(j + 2)[i].data().dyn_array().size());
                        ASSERT_TRUE(is_equal_uint(
                            keys.key(j + 2)[i].data().data(), test_keys.key(j + 2)[i].data().data(),
                            keys.key(j + 2)[i].data().dyn_array().size()));
                    }
                }
            }
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(256);
                parms.set_plain_modulus(1 << 6);
                parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 50 }));

                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);

                RelinKeys keys;
                RelinKeys test_keys;
                keygen.create_relin_keys(keys);
                keys.save(stream);
                test_keys.load(context, stream);
                ASSERT_EQ(keys.size(), test_keys.size());
                ASSERT_TRUE(keys.parms_id() == test_keys.parms_id());
                for (size_t j = 0; j < test_keys.size(); j++)
                {
                    for (size_t i = 0; i < test_keys.key(j + 2).size(); i++)
                    {
                        ASSERT_EQ(keys.key(j + 2)[i].data().size(), test_keys.key(j + 2)[i].data().size());
                        ASSERT_EQ(
                            keys.key(j + 2)[i].data().dyn_array().size(),
                            test_keys.key(j + 2)[i].data().dyn_array().size());
                        ASSERT_TRUE(is_equal_uint(
                            keys.key(j + 2)[i].data().data(), test_keys.key(j + 2)[i].data().data(),
                            keys.key(j + 2)[i].data().dyn_array().size()));
                    }
                }
            }
        };

        relin_keys_save_load(scheme_type::bfv);
        relin_keys_save_load(scheme_type::bgv);
    }

    TEST(RelinKeysTest, RelinKeysBitPackSaveLoad)
    {
        auto relin_keys_bitpack_save_load = [](scheme_type scheme) {
            EncryptionParameters parms(scheme);
            parms.set_poly_modulus_degree(256);
            parms.set_plain_modulus(65537);
            parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 50 }));
            SEALContext context(parms, false, sec_level_type::none);
            KeyGenerator keygen(context);

            auto compare_keys = [](const RelinKeys &a, const RelinKeys &b) {
                ASSERT_TRUE(a.parms_id() == b.parms_id());
                ASSERT_EQ(a.data().size(), b.data().size());
                for (size_t j = 0; j < a.data().size(); j++)
                {
                    ASSERT_EQ(a.data()[j].size(), b.data()[j].size());
                    for (size_t i = 0; i < a.data()[j].size(); i++)
                    {
                        ASSERT_EQ(a.data()[j][i].data().dyn_array().size(), b.data()[j][i].data().dyn_array().size());
                        ASSERT_TRUE(is_equal_uint(
                            a.data()[j][i].data().data(), b.data()[j][i].data().data(),
                            a.data()[j][i].data().dyn_array().size()));
                    }
                }
            };

            // Expanded keys round-trip bit-packed
            stringstream stream;
            RelinKeys keys;
            RelinKeys test_keys;
            keygen.create_relin_keys(keys);
            auto bitpack_size = keys.save(stream, compr_mode_type::bitpack);
            test_keys.load(context, stream);
            compare_keys(keys, test_keys);

            // The key data is uniformly random modulo the coefficient modulus primes, so bit-packing must beat
            // the unpacked size
            ASSERT_LT(bitpack_size, keys.save_size(compr_mode_type::none));

            // Seeded keys bit-pack too, with the seeded polynomials regenerated on load: the same seeded object
            // saved with and without bit-packing must load to identical keys
            stringstream seeded_stream;
            auto seeded = keygen.create_relin_keys();
            seeded.save(seeded_stream, compr_mode_type::bitpack);
            seeded.save(seeded_stream, compr_mode_type::none);
            RelinKeys from_bitpack;
            RelinKeys from_none;
            from_bitpack.load(context, seeded_stream);
            from_none.load(context, seeded_stream);
            compare_keys(from_bitpack, from_none);
        };
        relin_keys_bitpack_save_load(scheme_type::bfv);
        relin_keys_bitpack_save_load(scheme_type::bgv);
    }

    TEST(RelinKeysTest, RelinKeysSeededSaveLoad)
    {
        auto relin_keys_seeded_save_load = [](scheme_type scheme) {
            // Returns true if a, b contains the same error.
            auto compare_kswitchkeys = [](const KSwitchKeys &a, const KSwitchKeys &b, const SecretKey &sk,
                                          const SEALContext &context) {
                auto compare_error = [](const Ciphertext &a_ct, const Ciphertext &b_ct, const SecretKey &sk1,
                                        const SEALContext &context1) {
                    auto get_error = [](const Ciphertext &encrypted, const SecretKey &sk2,
                                        const SEALContext &context2) {
                        auto pool = MemoryManager::GetPool();
                        auto &context_data = *context2.get_context_data(encrypted.parms_id());
                        auto &parms = context_data.parms();
                        auto &coeff_modulus = parms.coeff_modulus();
                        size_t coeff_count = parms.poly_modulus_degree();
                        size_t coeff_modulus_size = coeff_modulus.size();
                        size_t rns_poly_uint64_count = util::mul_safe(coeff_count, coeff_modulus_size);

                        DynArray<Ciphertext::ct_coeff_type> error;
                        error.resize(rns_poly_uint64_count);
                        auto destination = error.begin();

                        auto copy_operand1(util::allocate_uint(coeff_count, pool));
                        for (size_t i = 0; i < coeff_modulus_size; i++)
                        {
                            // Initialize pointers for multiplication
                            const uint64_t *encrypted_ptr = encrypted.data(1) + (i * coeff_count);
                            const uint64_t *secret_key_ptr = sk2.data().data() + (i * coeff_count);
                            uint64_t *destination_ptr = destination + (i * coeff_count);
                            util::set_zero_uint(coeff_count, destination_ptr);
                            util::set_uint(encrypted_ptr, coeff_count, copy_operand1.get());
                            // compute c_{j+1} * s^{j+1}
                            util::dyadic_product_coeffmod(
                                copy_operand1.get(), secret_key_ptr, coeff_count, coeff_modulus[i],
                                copy_operand1.get());
                            // add c_{j+1} * s^{j+1} to destination
                            util::add_poly_coeffmod(
                                destination_ptr, copy_operand1.get(), coeff_count, coeff_modulus[i], destination_ptr);
                            // add c_0 into destination
                            util::add_poly_coeffmod(
                                destination_ptr, encrypted.data() + (i * coeff_count), coeff_count, coeff_modulus[i],
                                destination_ptr);
                        }
                        return error;
                    };

                    auto error_a = get_error(a_ct, sk1, context1);
                    auto error_b = get_error(b_ct, sk1, context1);
                    ASSERT_EQ(error_a.size(), error_b.size());
                    ASSERT_TRUE(is_equal_uint(error_a.cbegin(), error_b.cbegin(), error_a.size()));
                };

                ASSERT_EQ(a.size(), b.size());
                auto iter_a = a.data().begin();
                auto iter_b = b.data().begin();
                for (; iter_a != a.data().end(); iter_a++, iter_b++)
                {
                    ASSERT_EQ(iter_a->size(), iter_b->size());
                    auto pk_a = iter_a->begin();
                    auto pk_b = iter_b->begin();
                    for (; pk_a != iter_a->end(); pk_a++, pk_b++)
                    {
                        compare_error(pk_a->data(), pk_b->data(), sk, context);
                    }
                }
            };

            stringstream stream;
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(8);
                parms.set_plain_modulus(65537);
                parms.set_coeff_modulus(CoeffModulus::Create(8, { 60, 60 }));
                prng_seed_type seed = {};
                for (auto &i : seed)
                {
                    i = random_uint64();
                }
                auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
                parms.set_random_generator(rng);
                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);
                SecretKey secret_key = keygen.secret_key();

                keygen.create_relin_keys().save(stream);
                RelinKeys test_keys;
                test_keys.load(context, stream);
                RelinKeys keys;
                keygen.create_relin_keys(keys);
                compare_kswitchkeys(keys, test_keys, secret_key, context);
            }
            {
                EncryptionParameters parms(scheme);
                parms.set_poly_modulus_degree(256);
                parms.set_plain_modulus(65537);
                parms.set_coeff_modulus(CoeffModulus::Create(256, { 60, 50 }));
                prng_seed_type seed = {};
                for (auto &i : seed)
                {
                    i = random_uint64();
                }
                auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
                parms.set_random_generator(rng);
                SEALContext context(parms, false, sec_level_type::none);
                KeyGenerator keygen(context);
                SecretKey secret_key = keygen.secret_key();

                keygen.create_relin_keys().save(stream);
                RelinKeys test_keys;
                test_keys.load(context, stream);
                RelinKeys keys;
                keygen.create_relin_keys(keys);
                compare_kswitchkeys(keys, test_keys, secret_key, context);
            }
        };
        relin_keys_seeded_save_load(scheme_type::bfv);
        relin_keys_seeded_save_load(scheme_type::bgv);
    }

    TEST(RelinKeysTest, LoadOversizedDimensionsRejected)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        RelinKeys keys;
        keygen.create_relin_keys(keys);

        stringstream ss;
        keys.save(ss, compr_mode_type::none);
        string blob = ss.str();

        // Layout after the 16-byte SEALHeader: parms_id (32 bytes), then the outer
        // dimension (8 bytes) followed by the first inner dimension (8 bytes).
        const size_t dim1_offset = Serialization::seal_header_size + sizeof(parms_id_type);
        const size_t dim2_offset = dim1_offset + sizeof(uint64_t);
        ASSERT_GE(blob.size(), dim2_offset + sizeof(uint64_t));

        auto patched = [&](size_t offset, uint64_t value) {
            string out = blob;
            out.replace(offset, sizeof(uint64_t), string(reinterpret_cast<const char *>(&value), sizeof(uint64_t)));
            return out;
        };

        // The context permits at most poly_modulus_degree outer keys.
        {
            stringstream bad(patched(dim1_offset, uint64_t(SEAL_POLY_MOD_DEGREE_MAX)));
            RelinKeys loaded;
            ASSERT_THROW(loaded.load(context, bad), logic_error);
        }
        // The context permits at most first_context_data's coeff_modulus count inner keys.
        {
            stringstream bad(patched(dim2_offset, uint64_t(SEAL_COEFF_MOD_COUNT_MAX)));
            RelinKeys loaded;
            ASSERT_THROW(loaded.load(context, bad), logic_error);
        }
    }

    TEST(RelinKeysTest, LoadPreservesParmsIdOnFailure)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        RelinKeys keys;
        keygen.create_relin_keys(keys);

        stringstream ss;
        keys.save(ss, compr_mode_type::none);
        string blob = ss.str();

        // Trip the outer-dimension check, which throws after parms_id has been read.
        const size_t dim1_offset = Serialization::seal_header_size + sizeof(parms_id_type);
        ASSERT_GE(blob.size(), dim1_offset + sizeof(uint64_t));
        uint64_t oversized = uint64_t(SEAL_POLY_MOD_DEGREE_MAX);
        blob.replace(
            dim1_offset, sizeof(uint64_t), string(reinterpret_cast<const char *>(&oversized), sizeof(uint64_t)));

        RelinKeys loaded;
        parms_id_type before = loaded.parms_id();
        stringstream bad(blob);
        ASSERT_THROW(loaded.unsafe_load(context, bad), logic_error);
        ASSERT_TRUE(loaded.parms_id() == before);
    }

    // Keys in key-switching keys have size 2, and loading rejects larger keys before allocating memory for them.
    TEST(RelinKeysTest, LoadRejectsLargeKeys)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);

        KSwitchKeys keys = make_zero_keys(context, 1);
        for (auto &key : keys.data()[0])
        {
            key.data().resize(context, context.key_parms_id(), SEAL_CIPHERTEXT_SIZE_MIN + 1);
        }
        stringstream stream;
        keys.save(stream, compr_mode_type::none);
        string bytes = stream.str();

        // Keys loaded into loaded are allocated from pool
        MemoryPoolHandle pool = MemoryPoolHandle::New();
        unique_ptr<RelinKeys> loaded;
        {
            MMProfGuard guard(make_unique<MMProfFixed>(pool));
            loaded = make_unique<RelinKeys>();
        }
        ASSERT_TRUE(loaded->pool() == pool);

        stringstream in(bytes);
        ASSERT_THROW(loaded->load(context, in), logic_error);
        ASSERT_EQ(size_t(0), pool.alloc_byte_count());

        stringstream trusted_in(bytes);
        RelinKeys trusted_loaded;
        ASSERT_THROW(trusted_loaded.unsafe_load(context, trusted_in), logic_error);
    }

    // Loading keys rejects compressed data that expands far more than valid key data can. Loading from a trusted
    // source does not bound the expansion.
    TEST(RelinKeysTest, LoadBoundsCompressedExpansion)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);

        // 64 key sets of two zero keys
        KSwitchKeys keys = make_zero_keys(context, 64);
        auto raw_size = keys.save_size(compr_mode_type::none);

        // Uncompressed, the keys are valid and load
        {
            stringstream stream;
            keys.save(stream, compr_mode_type::none);
            KSwitchKeys loaded;
            loaded.load(context, stream);
            ASSERT_EQ(keys.data().size(), loaded.data().size());
        }

        for (auto compr_mode : compressed_modes())
        {
            stringstream stream;
            auto out_size = keys.save(stream, compr_mode);
            string bytes = stream.str();

            // The data expands far beyond 4 MiB plus 64 times the compressed size
            ASSERT_GT(raw_size, (streamoff(4) << 20) + 64 * out_size);

            {
                stringstream in(bytes);
                KSwitchKeys loaded;
                ASSERT_THROW(loaded.load(context, in), runtime_error);
            }
            {
                KSwitchKeys loaded;
                ASSERT_THROW(
                    loaded.load(context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size()),
                    runtime_error);
            }
            {
                stringstream in(bytes);
                RelinKeys loaded;
                ASSERT_THROW(loaded.load(context, in), runtime_error);
            }
            {
                stringstream in(bytes);
                GaloisKeys loaded;
                ASSERT_THROW(loaded.load(context, in), runtime_error);
            }
            {
                stringstream in(bytes);
                KSwitchKeys loaded;
                loaded.unsafe_load(context, in);
                ASSERT_EQ(keys.data().size(), loaded.data().size());
            }
        }
    }

    // Valid keys load in every compression mode, including seeded keys and keys larger than the bound's free
    // allowance. Keys with small primes compress the most.
    TEST(RelinKeysTest, LoadCompressedValidKeys)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 20, 20, 20 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        GaloisKeys galois_keys;
        keygen.create_galois_keys(vector<uint32_t>{ 3, 2 * 4096 - 1 }, galois_keys);
        auto seeded_relin_keys = keygen.create_relin_keys();
        auto seeded_galois_keys = keygen.create_galois_keys();
        ASSERT_GT(seeded_galois_keys.save_size(compr_mode_type::none), streamoff(4) << 20);
        auto galois_elts = context.key_context_data()->galois_tool()->get_elts_all();

        auto compr_modes = compressed_modes();
        compr_modes.push_back(compr_mode_type::none);
        for (auto compr_mode : compr_modes)
        {
            {
                stringstream stream;
                relin_keys.save(stream, compr_mode);
                RelinKeys loaded;
                loaded.load(context, stream);
                ASSERT_EQ(relin_keys.size(), loaded.size());
            }
            {
                stringstream stream;
                galois_keys.save(stream, compr_mode);
                GaloisKeys loaded;
                loaded.load(context, stream);
                ASSERT_EQ(galois_keys.size(), loaded.size());
            }
            {
                stringstream stream;
                seeded_relin_keys.save(stream, compr_mode);
                RelinKeys loaded;
                loaded.load(context, stream);
                ASSERT_EQ(relin_keys.size(), loaded.size());
            }
            {
                stringstream stream;
                seeded_galois_keys.save(stream, compr_mode);
                string bytes = stream.str();
                GaloisKeys loaded;
                loaded.load(context, reinterpret_cast<const seal_byte *>(bytes.data()), bytes.size());
                for (auto galois_elt : galois_elts)
                {
                    ASSERT_TRUE(loaded.has_key(galois_elt));
                }
            }
        }
    }

    // Galois keys hold an empty slot for each Galois element without a key, and these compress extremely well. A key
    // for only the highest Galois element follows the most empty slots, which the bound's free allowance covers.
    TEST(RelinKeysTest, LoadCompressedSparseGaloisKeys)
    {
        size_t poly_modulus_degree = SEAL_POLY_MOD_DEGREE_MAX;
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 30, 30 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        uint32_t galois_elt = static_cast<uint32_t>(2 * poly_modulus_degree - 1);
        GaloisKeys keys;
        keygen.create_galois_keys(vector<uint32_t>{ galois_elt }, keys);
        ASSERT_EQ(size_t(1), keys.size());

        auto compr_modes = compressed_modes();
        compr_modes.push_back(compr_mode_type::none);
        for (auto compr_mode : compr_modes)
        {
            stringstream stream;
            keys.save(stream, compr_mode);
            GaloisKeys loaded;
            loaded.load(context, stream);
            ASSERT_TRUE(loaded.has_key(galois_elt));
        }
    }

    // Microsoft SEAL never compresses the keys nested in key-switching keys, and loading keys rejects compressed nested
    // keys, so the bound on the expansion of compressed data applies to all of the key data.
    TEST(RelinKeysTest, LoadRejectsCompressedNestedKeys)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 40, 40, 40 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        RelinKeys keys;
        keygen.create_relin_keys(keys);

        // Saves keys uncompressed, with each nested key saved with nested_mode
        auto save_with_nested = [&](compr_mode_type nested_mode) {
            stringstream members;
            members.write(reinterpret_cast<const char *>(&keys.parms_id()), sizeof(parms_id_type));
            uint64_t key_set_count = keys.data().size();
            members.write(reinterpret_cast<const char *>(&key_set_count), sizeof(uint64_t));
            for (auto &key_set : keys.data())
            {
                uint64_t key_count = key_set.size();
                members.write(reinterpret_cast<const char *>(&key_count), sizeof(uint64_t));
                for (auto &key : key_set)
                {
                    key.save(members, nested_mode);
                }
            }
            string member_bytes = members.str();

            stringstream stream;
            Serialization::Save(
                [&](ostream &out) { out.write(member_bytes.data(), static_cast<streamsize>(member_bytes.size())); },
                static_cast<streamoff>(sizeof(Serialization::SEALHeader) + member_bytes.size()), stream,
                compr_mode_type::none, false);
            return stream.str();
        };

        {
            stringstream in(save_with_nested(compr_mode_type::none));
            RelinKeys loaded;
            loaded.load(context, in);
            ASSERT_EQ(keys.size(), loaded.size());
        }

        for (auto nested_mode : compressed_modes())
        {
            string bytes = save_with_nested(nested_mode);
            {
                stringstream in(bytes);
                RelinKeys loaded;
                ASSERT_THROW(loaded.load(context, in), logic_error);
            }

            // Loading from a trusted source accepts compressed nested keys
            {
                stringstream in(bytes);
                RelinKeys loaded;
                loaded.unsafe_load(context, in);
                ASSERT_EQ(keys.size(), loaded.size());
            }

            // The rejection does not affect later loads of compressed objects
            stringstream key_stream;
            keys.data()[0][0].save(key_stream, nested_mode);
            PublicKey key;
            key.unsafe_load(context, key_stream);
            ASSERT_TRUE(key.parms_id() == keys.parms_id());
        }
    }

    // Keys load as usual inside a user's own container, compressed or not, and the objects loaded after them in the
    // same container may be compressed.
    TEST(RelinKeysTest, LoadInsideUserContainer)
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(1024);
        parms.set_plain_modulus(1 << 6);
        parms.set_coeff_modulus(CoeffModulus::Create(1024, { 30, 30 }));

        SEALContext context(parms, false, sec_level_type::none);
        KeyGenerator keygen(context);

        RelinKeys keys;
        keygen.create_relin_keys(keys);
        PublicKey public_key;
        keygen.create_public_key(public_key);

        auto compr_modes = compressed_modes();
        compr_modes.push_back(compr_mode_type::none);
        for (auto container_mode : compr_modes)
        {
            for (auto compr_mode : compr_modes)
            {
                stringstream members;
                keys.save(members, compr_mode);
                public_key.save(members, compr_mode);
                string member_bytes = members.str();

                stringstream stream;
                Serialization::Save(
                    [&](ostream &out) { out.write(member_bytes.data(), static_cast<streamsize>(member_bytes.size())); },
                    static_cast<streamoff>(sizeof(Serialization::SEALHeader) + member_bytes.size()), stream,
                    container_mode, false);

                RelinKeys loaded_keys;
                PublicKey loaded_public_key;
                Serialization::Load(
                    [&](istream &in, SEALVersion) {
                        loaded_keys.load(context, in);
                        loaded_public_key.load(context, in);
                    },
                    stream, false);
                ASSERT_EQ(keys.size(), loaded_keys.size());
                ASSERT_TRUE(loaded_public_key.parms_id() == public_key.parms_id());
            }
        }
    }
} // namespace sealtest

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#endif
#include "benchmark/benchmark.h"
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif

#include "seal/seal.h"
#include "seal/util/rlwe.h"

namespace sealbench
{
    /**
    Class BMEnv contains a set of required precomputed/preconstructed objects to setup a benchmark case.
    A global BMEnv object is only initialized when a benchmark case for a EncryptionParameters is requested.
    Since benchmark cases for the same parameters are registered together, this avoids heavy precomputation.
    */
    class BMEnv
    {
    public:
        BMEnv() = delete;

        // Allow insecure parameters for experimental purposes.
        // DO NOT USE THIS AS AN EXAMPLE.
        BMEnv(const seal::EncryptionParameters &parms)
            : parms_(parms), context_(parms_, true, seal::sec_level_type::none)
        {
            keygen_ = std::make_shared<seal::KeyGenerator>(context_);
            sk_ = keygen_->secret_key();
            keygen_->create_public_key(pk_);
            if (context_.using_keyswitching())
            {
                keygen_->create_relin_keys(rlk_);
                galois_elts_all_ = context_.key_context_data()->galois_tool()->get_elts_from_steps({ 1 });
                galois_elts_all_.emplace_back(2 * static_cast<uint32_t>(parms_.poly_modulus_degree()) - 1);
                // galois_elts_all_ = context_.key_context_data()->galois_tool()->get_elts_all();
                keygen_->create_galois_keys(galois_elts_all_, glk_);
            }

            encryptor_ = std::make_shared<seal::Encryptor>(context_, pk_, sk_);
            decryptor_ = std::make_shared<seal::Decryptor>(context_, sk_);
            if (parms_.scheme() == seal::scheme_type::bfv || parms_.scheme() == seal::scheme_type::bgv)
            {
                batch_encoder_ = std::make_shared<seal::BatchEncoder>(context_);
            }
            else if (parms_.scheme() == seal::scheme_type::ckks)
            {
                ckks_encoder_ = std::make_shared<seal::CKKSEncoder>(context_);
            }
            evaluator_ = std::make_shared<seal::Evaluator>(context_);

            pt_.resize(std::size_t(2));
            for (std::size_t i = 0; i < 2; i++)
            {
                pt_[i].resize(parms_.poly_modulus_degree());
            }

            ct_.resize(std::size_t(3));
            for (std::size_t i = 0; i < 3; i++)
            {
                ct_[i].resize(context_, std::size_t(2));
            }
        }

        /**
        Getter methods.
        */
        SEAL_NODISCARD const seal::EncryptionParameters &parms() const
        {
            return parms_;
        }

        SEAL_NODISCARD const seal::SEALContext &context() const
        {
            return context_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::KeyGenerator> keygen()
        {
            return keygen_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Encryptor> encryptor()
        {
            return encryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Decryptor> decryptor()
        {
            return decryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::BatchEncoder> batch_encoder()
        {
            return batch_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::CKKSEncoder> ckks_encoder()
        {
            return ckks_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Evaluator> evaluator()
        {
            return evaluator_;
        }

        SEAL_NODISCARD seal::SecretKey &sk()
        {
            return sk_;
        }

        SEAL_NODISCARD const seal::SecretKey &sk() const
        {
            return sk_;
        }

        SEAL_NODISCARD seal::PublicKey &pk()
        {
            return pk_;
        }

        SEAL_NODISCARD const seal::PublicKey &pk() const
        {
            return pk_;
        }

        SEAL_NODISCARD seal::RelinKeys &rlk()
        {
            return rlk_;
        }

        SEAL_NODISCARD const seal::RelinKeys &rlk() const
        {
            return rlk_;
        }

        SEAL_NODISCARD seal::GaloisKeys &glk()
        {
            return glk_;
        }

        SEAL_NODISCARD const seal::GaloisKeys &glk() const
        {
            return glk_;
        }

        SEAL_NODISCARD const std::vector<std::uint32_t> &galois_elts_all() const
        {
            return galois_elts_all_;
        }

        SEAL_NODISCARD std::vector<std::uint64_t> &msg_uint64()
        {
            return msg_uint64_;
        }

        SEAL_NODISCARD std::vector<double> &msg_double()
        {
            return msg_double_;
        }

        SEAL_NODISCARD std::vector<seal::Plaintext> &pt()
        {
            return pt_;
        }

        SEAL_NODISCARD std::vector<seal::Ciphertext> &ct()
        {
            return ct_;
        }

        /**
        In most cases, the scale is chosen half as large as the second last prime (or the last if there is only one).
        This avoids "scale out of bound" error in ciphertext/plaintext multiplications.
        */
        SEAL_NODISCARD double safe_scale()
        {
            return pow(2.0, (context_.first_context_data()->parms().coeff_modulus().end() - 1)->bit_count() / 2 - 1);
        }

        /**
        Fill a buffer with a number of random values that are uniformly samples from 0 ~ modulus - 1.
        */
        void randomize_array_mod(std::uint64_t *data, std::size_t count, const seal::Modulus &modulus)
        {
            // For the purpose of benchmark, avoid using seal::UniformRandomGenerator, as it degrades
            // performance with HEXL on some systems, due to AVX512 transitions.
            // See https://travisdowns.github.io/blog/2020/01/17/avxfreq1.html#voltage-only-transitions.
            // This method is not used for random number generation in Microsoft SEAL.
            std::random_device rd;
            std::mt19937_64 generator(rd());
            std::uniform_int_distribution<std::uint64_t> dist(0, modulus.value() - 1);
            std::generate(data, data + count, [&]() { return dist(generator); });
        }

        /**
        Sample an RNS polynomial from uniform distribution.
        */
        void randomize_poly_rns(std::uint64_t *data, const seal::EncryptionParameters &parms)
        {
            std::size_t coeff_count = parms.poly_modulus_degree();
            std::vector<seal::Modulus> coeff_modulus = parms.coeff_modulus();
            for (auto &i : coeff_modulus)
            {
                randomize_array_mod(data, coeff_count, i);
                data += coeff_count;
            }
        }

        /**
        Create a uniform random ciphertext in BFV using the highest-level parameters.
        */
        void randomize_ct_bfv(seal::Ciphertext &ct)
        {
            if (ct.parms_id() != context_.first_parms_id())
            {
                ct.resize(context_, std::size_t(2));
            }
            auto &parms = context_.first_context_data()->parms();
            for (std::size_t i = 0; i < ct.size(); i++)
            {
                randomize_poly_rns(ct.data(i), parms);
            }
            ct.is_ntt_form() = false;
        }

        /**
        Create a uniform random ciphertext in BGV using the highest-level parameters.
        */
        void randomize_ct_bgv(seal::Ciphertext &ct)
        {
            if (ct.parms_id() != context_.first_parms_id())
            {
                ct.resize(context_, std::size_t(2));
            }
            auto &parms = context_.first_context_data()->parms();
            for (std::size_t i = 0; i < ct.size(); i++)
            {
                randomize_poly_rns(ct.data(i), parms);
            }
            ct.is_ntt_form() = true;
        }

        /**
        Create a uniform random ciphertext in CKKS using the highest-level parameters.
        */
        void randomize_ct_ckks(seal::Ciphertext &ct)
        {
            if (ct.parms_id() != context_.first_parms_id())
            {
                ct.resize(context_, std::size_t(2));
            }
            auto &parms = context_.first_context_data()->parms();
            for (std::size_t i = 0; i < ct.size(); i++)
            {
                randomize_poly_rns(ct.data(i), parms);
            }
            ct.is_ntt_form() = true;
        }

        /**
        Create a uniform random plaintext (single modulus) in BFV.
        */
        void randomize_pt_bfv(seal::Plaintext &pt)
        {
            pt.resize(parms_.poly_modulus_degree());
            pt.parms_id() = seal::parms_id_zero;
            randomize_array_mod(pt.data(), parms_.poly_modulus_degree(), parms_.plain_modulus());
        }

        /**
        Create a uniform random plaintext (single modulus) in BGV.
        */
        void randomize_pt_bgv(seal::Plaintext &pt)
        {
            randomize_pt_bfv(pt);
        }

        /**
        Create a uniform random plaintext (RNS poly) in CKKS.
        */
        void randomize_pt_ckks(seal::Plaintext &pt)
        {
            auto &parms = context_.first_context_data()->parms();
            if (pt.coeff_count() != parms.poly_modulus_degree() * parms.coeff_modulus().size())
            {
                pt.parms_id() = seal::parms_id_zero;
                pt.resize(parms.poly_modulus_degree() * parms.coeff_modulus().size());
            }
            if (pt.parms_id() != context_.first_parms_id())
            {
                pt.parms_id() = context_.first_parms_id();
            }
            randomize_poly_rns(pt.data(), parms);
        }

        /**
        Create a vector of slot_count uniform random integers modulo plain_modululs.
        */
        void randomize_message_uint64(std::vector<std::uint64_t> &msg)
        {
            msg.resize(batch_encoder_->slot_count());
            randomize_array_mod(msg.data(), batch_encoder_->slot_count(), parms_.plain_modulus());
        }

        /**
        Create a vector of slot_count uniform random double precision values in [0, 1).
        */
        void randomize_message_double(std::vector<double> &msg)
        {
            msg.resize(ckks_encoder_->slot_count());
            std::generate(msg.begin(), msg.end(), []() { return static_cast<double>(std::rand()) / RAND_MAX; });
        }

    private:
        seal::EncryptionParameters parms_;
        seal::SEALContext context_;
        std::shared_ptr<seal::KeyGenerator> keygen_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
        std::shared_ptr<seal::BatchEncoder> batch_encoder_{ nullptr };
        std::shared_ptr<seal::CKKSEncoder> ckks_encoder_{ nullptr };
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };

        /**
        The following data members are created as input/output containers for benchmark cases.
        This avoids repeated and unnecessary allocation/deallocation in benchmark runs.
        */
        seal::SecretKey sk_;
        seal::PublicKey pk_;
        seal::RelinKeys rlk_;
        seal::GaloisKeys glk_;
        std::vector<std::uint32_t> galois_elts_all_;
        std::vector<std::uint64_t> msg_uint64_;
        std::vector<double> msg_double_;
        std::vector<seal::Plaintext> pt_;
        std::vector<seal::Ciphertext> ct_;
    }; // namespace BMEnv

    // NTT benchmark cases
    void bm_util_ntt_forward(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_forward_low_level(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse_low_level(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_forward_low_level_lazy(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse_low_level_lazy(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // KeyGen benchmark cases
    void bm_keygen_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_relin(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_galois(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // BFV-specific benchmark cases
    void bm_bfv_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_encode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_decode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_negate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_sub_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_sub_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_modswitch_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_rotate_rows(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_rotate_cols(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // BGV-specific benchmark cases
    void bm_bgv_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_encode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_decode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_negate(benchmark::State &state, std::shared_ptr<BMEnv>);
    void bm_bgv_negate_inplace(benchmark::State &state, std::shared_ptr<BMEnv>);
    void bm_bgv_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_ct_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_pt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_ct_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_pt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_square_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_modswitch_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_rows(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_rows_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_cols(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_cols_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_to_ntt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_from_ntt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // CKKS-specific benchmark cases
    void bm_ckks_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_encode_double(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_decode_double(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_negate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_sub_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_sub_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_rescale_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_rotate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
} // namespace sealbench

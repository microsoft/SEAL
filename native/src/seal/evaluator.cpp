// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/evaluator.h"
#include "seal/util/common.h"
#include "seal/util/galois.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/scalingvariant.h"
#include "seal/util/uintarith.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>

using namespace std;
using namespace seal::util;

namespace seal
{
    namespace
    {
        template <typename T, typename S>
        SEAL_NODISCARD inline bool are_same_scale(const T &value1, const S &value2) noexcept
        {
            return util::are_close<double>(value1.scale(), value2.scale());
        }

        SEAL_NODISCARD inline bool is_scale_within_bounds(
            double scale, const SEALContext::ContextData &context_data) noexcept
        {
            int scale_bit_count_bound = 0;
            switch (context_data.parms().scheme())
            {
            case scheme_type::bfv:
            case scheme_type::bgv:
                scale_bit_count_bound = context_data.parms().plain_modulus().bit_count();
                break;
            case scheme_type::ckks:
                scale_bit_count_bound = context_data.total_coeff_modulus_bit_count();
                break;
            default:
                // Unsupported scheme; check will fail
                scale_bit_count_bound = -1;
            };

            return !(!isnormal(scale) || scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
        }

        /**
        Returns (f, e1, e2) such that
        (1) e1 * factor1 = e2 * factor2 = f mod p;
        (2) gcd(e1, p) = 1 and gcd(e2, p) = 1;
        (3) abs(e1_bal) + abs(e2_bal) is minimal, where e1_bal and e2_bal represent e1 and e2 in (-p/2, p/2].
        */
        SEAL_NODISCARD inline auto balance_correction_factors(
            uint64_t factor1, uint64_t factor2, const Modulus &plain_modulus) -> tuple<uint64_t, uint64_t, uint64_t>
        {
            uint64_t t = plain_modulus.value();
            uint64_t half_t = t / 2;

            auto sum_abs = [&](uint64_t x, uint64_t y) {
                int64_t x_bal = static_cast<int64_t>(x > half_t ? x - t : x);
                int64_t y_bal = static_cast<int64_t>(y > half_t ? y - t : y);
                return abs(x_bal) + abs(y_bal);
            };

            // ratio = f2 / f1 mod p
            uint64_t ratio = 1;
            if (!try_invert_uint_mod(factor1, plain_modulus, ratio))
            {
                throw logic_error("invalid correction factor1");
            }
            ratio = multiply_uint_mod(ratio, factor2, plain_modulus);
            uint64_t e1 = ratio;
            uint64_t e2 = 1;
            int64_t sum = sum_abs(e1, e2);

            // Extended Euclidean
            int64_t prev_a = static_cast<int64_t>(plain_modulus.value());
            int64_t prev_b = static_cast<int64_t>(0);
            int64_t a = static_cast<int64_t>(ratio);
            int64_t b = 1;

            while (a != 0)
            {
                int64_t q = prev_a / a;
                int64_t temp = prev_a % a;
                prev_a = a;
                a = temp;

                temp = sub_safe(prev_b, mul_safe(b, q));
                prev_b = b;
                b = temp;

                uint64_t a_mod = barrett_reduce_64(static_cast<uint64_t>(abs(a)), plain_modulus);
                if (a < 0)
                {
                    a_mod = negate_uint_mod(a_mod, plain_modulus);
                }
                uint64_t b_mod = barrett_reduce_64(static_cast<uint64_t>(abs(b)), plain_modulus);
                if (b < 0)
                {
                    b_mod = negate_uint_mod(b_mod, plain_modulus);
                }
                if (a_mod != 0 && gcd(a_mod, t) == 1) // which also implies gcd(b_mod, t) == 1
                {
                    int64_t new_sum = sum_abs(a_mod, b_mod);
                    if (new_sum < sum)
                    {
                        sum = new_sum;
                        e1 = a_mod;
                        e2 = b_mod;
                    }
                }
            }
            return make_tuple(multiply_uint_mod(e1, factor1, plain_modulus), e1, e2);
        }

        // Throws if encrypted is not in the NTT form required by scheme
        void validate_ntt_form(const Ciphertext &encrypted, scheme_type scheme)
        {
            if (scheme == scheme_type::bfv && encrypted.is_ntt_form())
            {
                throw invalid_argument("BFV encrypted cannot be in NTT form");
            }
            if (scheme == scheme_type::ckks && !encrypted.is_ntt_form())
            {
                throw invalid_argument("CKKS encrypted must be in NTT form");
            }
            if (scheme == scheme_type::bgv && !encrypted.is_ntt_form())
            {
                throw invalid_argument("BGV encrypted must be in NTT form");
            }
        }

        // Throws if key_vector cannot key switch a polynomial with decomp_modulus_size RNS components. There is a key
        // for every RNS component at the first level, so key_vector may be longer than decomp_modulus_size.
        void validate_kswitch_key_vector(
            const vector<PublicKey> &key_vector, size_t decomp_modulus_size, const SEALContext &context)
        {
            if (key_vector.size() < decomp_modulus_size)
            {
                throw invalid_argument("kswitch_keys inner dimension is too small");
            }
            for (auto &each_key : key_vector)
            {
                if (!is_metadata_valid_for(each_key, context) || !is_buffer_valid(each_key))
                {
                    throw invalid_argument("kswitch_keys is not valid for encryption parameters");
                }
            }
        }

        // Throws if Evaluator::apply_galois_inplace cannot apply galois_elt to encrypted with galois_keys
        void validate_galois(
            const SEALContext &context, const Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys)
        {
            if (!is_metadata_valid_for(encrypted, context) || !is_buffer_valid(encrypted))
            {
                throw invalid_argument("encrypted is not valid for encryption parameters");
            }

            // Don't validate all of galois_keys but just check the parms_id.
            if (galois_keys.parms_id() != context.key_parms_id())
            {
                throw invalid_argument("galois_keys is not valid for encryption parameters");
            }

            auto &parms = context.get_context_data(encrypted.parms_id())->parms();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t coeff_modulus_size = parms.coeff_modulus().size();

            // Size check
            if (!product_fits_in(coeff_count, coeff_modulus_size))
            {
                throw logic_error("invalid parameters");
            }

            // Check if Galois key is generated or not.
            if (!galois_keys.has_key(galois_elt))
            {
                throw invalid_argument("Galois key not present");
            }

            uint64_t m = mul_safe(static_cast<uint64_t>(coeff_count), uint64_t(2));
            if (!(galois_elt & 1) || unsigned_geq(galois_elt, m))
            {
                throw invalid_argument("Galois element is not valid");
            }
            if (encrypted.size() != 2)
            {
                throw invalid_argument("encrypted size must be 2");
            }
            validate_ntt_form(encrypted, parms.scheme());

            if (!context.using_keyswitching())
            {
                throw logic_error("keyswitching is not supported by the context");
            }
            validate_kswitch_key_vector(
                galois_keys.data(GaloisKeys::get_index(galois_elt)), coeff_modulus_size, context);
        }

    } // namespace

    Evaluator::Evaluator(const SEALContext &context) : context_(context)
    {
        // Verify parameters
        if (!context_.parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
    }

    void Evaluator::negate_inplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t encrypted_size = encrypted.size();

        // Negate each poly in the array
        negate_poly_coeffmod(encrypted, encrypted_size, coeff_modulus, encrypted);
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::add_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correction_factor() != encrypted2.correction_factor())
        {
            // Balance correction factors and multiply by scalars before addition in BGV
            auto factors = balance_correction_factors(
                encrypted1.correction_factor(), encrypted2.correction_factor(), plain_modulus);
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted1.data(), coeff_count, coeff_modulus_size), encrypted1.size(), get<1>(factors),
                coeff_modulus, PolyIter(encrypted1.data(), coeff_count, coeff_modulus_size));

            Ciphertext encrypted2_copy = encrypted2;
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted2.data(), coeff_count, coeff_modulus_size), encrypted2.size(), get<2>(factors),
                coeff_modulus, PolyIter(encrypted2_copy.data(), coeff_count, coeff_modulus_size));

            // Set new correction factor
            encrypted1.correction_factor() = get<0>(factors);
            encrypted2_copy.correction_factor() = get<0>(factors);

            add_inplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parms_id(), max_count);
            // Add ciphertexts
            add_poly_coeffmod(encrypted1, encrypted2, min_count, coeff_modulus, encrypted1);

            // Copy the remainding polys of the array with larger count into encrypted1
            if (encrypted1_size < encrypted2_size)
            {
                set_poly_array(
                    encrypted2.data(min_count), encrypted2_size - encrypted1_size, coeff_count, coeff_modulus_size,
                    encrypted1.data(encrypted1_size));
            }
        }

#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::add_many(const vector<Ciphertext> &encrypteds, Ciphertext &destination) const
    {
        if (encrypteds.empty())
        {
            throw invalid_argument("encrypteds cannot be empty");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // add_inplace validates encrypteds[1..] but never sees encrypteds[0], so check it here.
        // A one-element vector would otherwise skip validation entirely.
        if (!is_metadata_valid_for(encrypteds[0], context_) || !is_buffer_valid(encrypteds[0]))
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Accumulate into a temporary so that a throw from add_inplace leaves destination
        // holding its previous value. The temporary uses destination's pool so that committing
        // it does not change which pool destination draws from.
        Ciphertext result(destination.pool());
        result = encrypteds[0];
        for (size_t i = 1; i < encrypteds.size(); i++)
        {
            add_inplace(result, encrypteds[i]);
        }
        destination = std::move(result);
    }

    void Evaluator::sub_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.is_ntt_form() != encrypted2.is_ntt_form())
        {
            throw invalid_argument("NTT form mismatch");
        }
        if (!are_same_scale(encrypted1, encrypted2))
        {
            throw invalid_argument("scale mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();
        size_t max_count = max(encrypted1_size, encrypted2_size);
        size_t min_count = min(encrypted1_size, encrypted2_size);

        // Size check
        if (!product_fits_in(max_count, coeff_count))
        {
            throw logic_error("invalid parameters");
        }

        if (encrypted1.correction_factor() != encrypted2.correction_factor())
        {
            // Balance correction factors and multiply by scalars before subtraction in BGV
            auto factors = balance_correction_factors(
                encrypted1.correction_factor(), encrypted2.correction_factor(), plain_modulus);

            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted1.data(), coeff_count, coeff_modulus_size), encrypted1.size(), get<1>(factors),
                coeff_modulus, PolyIter(encrypted1.data(), coeff_count, coeff_modulus_size));

            Ciphertext encrypted2_copy = encrypted2;
            multiply_poly_scalar_coeffmod(
                ConstPolyIter(encrypted2.data(), coeff_count, coeff_modulus_size), encrypted2.size(), get<2>(factors),
                coeff_modulus, PolyIter(encrypted2_copy.data(), coeff_count, coeff_modulus_size));

            // Set new correction factor
            encrypted1.correction_factor() = get<0>(factors);
            encrypted2_copy.correction_factor() = get<0>(factors);

            sub_inplace(encrypted1, encrypted2_copy);
        }
        else
        {
            // Prepare destination
            encrypted1.resize(context_, context_data.parms_id(), max_count);

            // Subtract ciphertexts
            sub_poly_coeffmod(encrypted1, encrypted2, min_count, coeff_modulus, encrypted1);

            // If encrypted2 has larger count, negate remaining entries
            if (encrypted1_size < encrypted2_size)
            {
                negate_poly_coeffmod(
                    iter(encrypted2) + min_count, encrypted2_size - min_count, coeff_modulus,
                    iter(encrypted1) + min_count);
            }
        }

#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_inplace(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted1, context_) || !is_buffer_valid(encrypted1))
        {
            throw invalid_argument("encrypted1 is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(encrypted2, context_) || !is_buffer_valid(encrypted2))
        {
            throw invalid_argument("encrypted2 is not valid for encryption parameters");
        }
        if (encrypted1.parms_id() != encrypted2.parms_id())
        {
            throw invalid_argument("encrypted1 and encrypted2 parameter mismatch");
        }
        if (encrypted1.size() < SEAL_CIPHERTEXT_SIZE_MIN || encrypted2.size() < SEAL_CIPHERTEXT_SIZE_MIN)
        {
            throw invalid_argument("encrypted1 and encrypted2 must have size at least 2");
        }

        auto context_data_ptr = context_.first_context_data();
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            bfv_multiply(encrypted1, encrypted2, pool);
            break;

        case scheme_type::ckks:
            ckks_multiply(encrypted1, encrypted2, pool);
            break;

        case scheme_type::bgv:
            bgv_multiply(encrypted1, encrypted2, pool);
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted1.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::bfv_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (encrypted1.is_ntt_form() || encrypted2.is_ntt_form())
        {
            throw invalid_argument("encrypted1 or encrypted2 cannot be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t base_q_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        auto rns_tool = context_data.rns_tool();
        size_t base_Bsk_size = rns_tool->base_Bsk()->size();
        size_t base_Bsk_m_tilde_size = rns_tool->base_Bsk_m_tilde()->size();

        // Determine destination.size()
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, base_Bsk_m_tilde_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterators for bases
        auto base_q = iter(parms.coeff_modulus());
        auto base_Bsk = iter(rns_tool->base_Bsk()->base());

        // Set up iterators for NTT tables
        auto base_q_ntt_tables = iter(context_data.small_ntt_tables());
        auto base_Bsk_ntt_tables = iter(rns_tool->base_Bsk_ntt_tables());

        // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
        // following steps:
        //
        // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
        // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
        // (3) Transform the data to NTT form
        // (4) Compute the ciphertext polynomial product using dyadic multiplication
        // (5) Transform the data back from NTT form
        // (6) Multiply the result by t (plain_modulus)
        // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
        // (8) Use Shenoy-Kumaresan method to convert the result to base q

        // If encrypted1 and encrypted2 are the same object (squaring), steps (1)-(3) need to be done only once
        const bool same_input = (&encrypted1 == &encrypted2);

        // Resize encrypted1 to destination size; this preserves the first encrypted1_size (and encrypted2_size, in
        // case of aliasing) polynomials
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // This lambda function takes as input an IterTuple with three components:
        //
        // 1. (Const)RNSIter to read an input polynomial from
        // 2. RNSIter for the output in base q
        // 3. RNSIter for the output in base Bsk
        //
        // It performs steps (1)-(3) of the BEHZ multiplication (see above) on the given input polynomial (given as an
        // RNSIter or ConstRNSIter) and writes the results in base q and base Bsk to the given output
        // iterators.
        auto behz_extend_base_convert_to_ntt = [&](auto I) {
            // Convert the input polynomial (in base q) to NTT form out of place, keeping the input intact
            // Lazy reduction
            ntt_negacyclic_harvey_lazy(get<0>(I), base_q_size, base_q_ntt_tables, get<1>(I));

            // (1) Convert from base q to base Bsk U {m_tilde}
            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            // These are fused together; the result is congruent to calling fastbconv_m_tilde followed by sm_mrq,
            // and reduced only to [0, 3m) for each prime m in Bsk, which suffices for the lazy NTT below.
            rns_tool->fastbconv_m_tilde_sm_mrq(get<0>(I), /*lazy_output=*/true, get<2>(I), pool);

            // Transform to NTT form in base Bsk
            // Lazy reduction
            ntt_negacyclic_harvey_lazy(get<2>(I), base_Bsk_size, base_Bsk_ntt_tables);
        };

        // Allocate space for a base q output of behz_extend_base_convert_to_ntt for encrypted1
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_q, encrypted1_size, coeff_count, base_q_size, pool);

        // Allocate space for a base Bsk output of behz_extend_base_convert_to_ntt for encrypted1
        SEAL_ALLOCATE_GET_POLY_ITER(encrypted1_Bsk, encrypted1_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ steps (1)-(3) for encrypted1
        SEAL_ITERATE(iter(encrypted1, encrypted1_q, encrypted1_Bsk), encrypted1_size, behz_extend_base_convert_to_ntt);

        // Repeat for encrypted2, unless it is the same as encrypted1
        ConstPolyIter encrypted2_q = encrypted1_q;
        ConstPolyIter encrypted2_Bsk = encrypted1_Bsk;
        Pointer<uint64_t> encrypted2_q_alloc;
        Pointer<uint64_t> encrypted2_Bsk_alloc;
        if (!same_input)
        {
            encrypted2_q_alloc = allocate_poly_array(encrypted2_size, coeff_count, base_q_size, pool);
            encrypted2_Bsk_alloc = allocate_poly_array(encrypted2_size, coeff_count, base_Bsk_size, pool);
            PolyIter encrypted2_q_iter(encrypted2_q_alloc.get(), coeff_count, base_q_size);
            PolyIter encrypted2_Bsk_iter(encrypted2_Bsk_alloc.get(), coeff_count, base_Bsk_size);
            SEAL_ITERATE(
                iter(encrypted2, encrypted2_q_iter, encrypted2_Bsk_iter), encrypted2_size,
                behz_extend_base_convert_to_ntt);
            encrypted2_q = encrypted2_q_iter;
            encrypted2_Bsk = encrypted2_Bsk_iter;
        }

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components. These do not need to be
        // initialized since behz_tensor_product writes every coefficient.
        SEAL_ALLOCATE_GET_POLY_ITER(temp_dest_q, dest_size, coeff_count, base_q_size, pool);
        SEAL_ALLOCATE_GET_POLY_ITER(temp_dest_Bsk, dest_size, coeff_count, base_Bsk_size, pool);

        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts, both for base q and base Bsk
        behz_tensor_product(
            encrypted1_q, encrypted1_size, encrypted2_q, encrypted2_size, base_q, base_q_size, coeff_count, temp_dest_q,
            pool);
        behz_tensor_product(
            encrypted1_Bsk, encrypted1_size, encrypted2_Bsk, encrypted2_size, base_Bsk, base_Bsk_size, coeff_count,
            temp_dest_Bsk, pool);

        // Perform BEHZ steps (5)-(8) one output polynomial at a time
        SEAL_ITERATE(iter(temp_dest_q, temp_dest_Bsk, encrypted1), dest_size, [&](auto I) {
            // Step (5): transform data from NTT form
            // Step (6): multiply by t (plain_modulus)
            // Step (7): divide by q and floor, producing a result in base Bsk
            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            // The scalar multiplications (including the factor 2^64 if the tensor product is in Montgomery form) are
            // folded into the inverse NTTs.
            rns_tool->inverse_ntt_multiply_t_fast_floor_fastbconv_sk(
                get<0>(I), get<1>(I), base_q_ntt_tables, behz_tensor_product_montgomery_form, get<2>(I), pool);
        });
    }

    void Evaluator::ckks_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (!(encrypted1.is_ntt_form() && encrypted2.is_ntt_form()))
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertexts
        PolyIter encrypted1_iter = iter(encrypted1);
        ConstPolyIter encrypted2_iter = iter(encrypted2);

        if (dest_size == 3)
        {
            // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
            // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67 coefficients per polynomial,
            // we should keep the tile size at 682 or below. The tile size must divide coeff_count, i.e. be a power of
            // two. Some testing shows similar performance with tile size 256 and 512, and worse performance on smaller
            // tiles. We pick the smaller of the two to prevent L1 cache misses on processors with < 32 KiB L1 cache.
            size_t tile_size = min<size_t>(coeff_count, size_t(256));
            size_t num_tiles = coeff_count / tile_size;
#ifdef SEAL_DEBUG
            if (coeff_count % tile_size != 0)
            {
                throw invalid_argument("tile_size does not divide coeff_count");
            }
#endif

            // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor in sequence
            ConstRNSIter encrypted2_0_iter(*encrypted2_iter[0], tile_size);
            ConstRNSIter encrypted2_1_iter(*encrypted2_iter[1], tile_size);
            RNSIter encrypted1_0_iter(*encrypted1_iter[0], tile_size);
            RNSIter encrypted1_1_iter(*encrypted1_iter[1], tile_size);
            RNSIter encrypted1_2_iter(*encrypted1_iter[2], tile_size);

            // Temporary buffer to store intermediate results
            SEAL_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

            // Computes the output tile_size coefficients at a time
            // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
            // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
            // with appropriate modular reduction
            SEAL_ITERATE(coeff_modulus, coeff_modulus_size, [&](auto I) {
                SEAL_ITERATE(iter(size_t(0)), num_tiles, [&](SEAL_MAYBE_UNUSED auto J) {
                    // Compute third output polynomial, overwriting input
                    // x[2] = x[1] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_1_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_2_iter[0]);

                    // Compute second output polynomial, overwriting input
                    // temp = x[1] * y[0]
                    dyadic_product_coeffmod(encrypted1_1_iter[0], encrypted2_0_iter[0], tile_size, I, temp);
                    // x[1] = x[0] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_1_iter[0]);
                    // x[1] += temp
                    add_poly_coeffmod(encrypted1_1_iter[0], temp, tile_size, I, encrypted1_1_iter[0]);

                    // Compute first output polynomial, overwriting input
                    // x[0] = x[0] * y[0]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_0_iter[0], tile_size, I, encrypted1_0_iter[0]);

                    // Manually increment iterators
                    encrypted1_0_iter++;
                    encrypted1_1_iter++;
                    encrypted1_2_iter++;
                    encrypted2_0_iter++;
                    encrypted2_1_iter++;
                });
            });
        }
        else
        {
            // Allocate temporary space for the result
            SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

            SEAL_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
                // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
                // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
                // the relevant terms are obtained as follows.
                size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
                size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
                size_t curr_encrypted1_first = I - curr_encrypted2_first;
                // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_encrypted2_iter = reverse_iter(encrypted2_iter + curr_encrypted2_first);

                SEAL_ITERATE(iter(shifted_encrypted1_iter, shifted_reversed_encrypted2_iter), steps, [&](auto J) {
                    // Extra care needed here:
                    // temp_iter must be dereferenced once to produce an appropriate RNSIter
                    SEAL_ITERATE(iter(J, coeff_modulus, temp[I]), coeff_modulus_size, [&](auto K) {
                        SEAL_ALLOCATE_GET_COEFF_ITER(prod, coeff_count, pool);
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), prod);
                        add_poly_coeffmod(prod, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                    });
                });
            });

            // Set the final result
            set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, encrypted1.data());
        }

        // Set the scale
        encrypted1.scale() *= encrypted2.scale();
        if (!is_scale_within_bounds(encrypted1.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgv_multiply(Ciphertext &encrypted1, const Ciphertext &encrypted2, MemoryPoolHandle pool) const
    {
        if (!encrypted1.is_ntt_form() || !encrypted2.is_ntt_form())
        {
            throw invalid_argument("encrypted1 or encrypted2 must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted1.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted1_size = encrypted1.size();
        size_t encrypted2_size = encrypted2.size();

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted1_size, encrypted2_size), size_t(1));

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted1.resize(context_, context_data.parms_id(), dest_size);

        // Convert c0 and c1 to ntt
        // Set up iterators for input ciphertexts
        PolyIter encrypted1_iter = iter(encrypted1);
        ConstPolyIter encrypted2_iter = iter(encrypted2);

        if (dest_size == 3)
        {
            // We want to keep six polynomials in the L1 cache: x[0], x[1], x[2], y[0], y[1], temp.
            // For a 32KiB cache, which can store 32768 / 8 = 4096 coefficients, = 682.67 coefficients per polynomial,
            // we should keep the tile size at 682 or below. The tile size must divide coeff_count, i.e. be a power of
            // two. Some testing shows similar performance with tile size 256 and 512, and worse performance on smaller
            // tiles. We pick the smaller of the two to prevent L1 cache misses on processors with < 32 KiB L1 cache.
            size_t tile_size = min<size_t>(coeff_count, size_t(256));
            size_t num_tiles = coeff_count / tile_size;
#ifdef SEAL_DEBUG
            if (coeff_count % tile_size != 0)
            {
                throw invalid_argument("tile_size does not divide coeff_count");
            }
#endif

            // Semantic misuse of RNSIter; each is really pointing to the data for each RNS factor in sequence
            ConstRNSIter encrypted2_0_iter(*encrypted2_iter[0], tile_size);
            ConstRNSIter encrypted2_1_iter(*encrypted2_iter[1], tile_size);
            RNSIter encrypted1_0_iter(*encrypted1_iter[0], tile_size);
            RNSIter encrypted1_1_iter(*encrypted1_iter[1], tile_size);
            RNSIter encrypted1_2_iter(*encrypted1_iter[2], tile_size);

            // Temporary buffer to store intermediate results
            SEAL_ALLOCATE_GET_COEFF_ITER(temp, tile_size, pool);

            // Computes the output tile_size coefficients at a time
            // Given input tuples of polynomials x = (x[0], x[1], x[2]), y = (y[0], y[1]), computes
            // x = (x[0] * y[0], x[0] * y[1] + x[1] * y[0], x[1] * y[1])
            // with appropriate modular reduction
            SEAL_ITERATE(coeff_modulus, coeff_modulus_size, [&](auto I) {
                SEAL_ITERATE(iter(size_t(0)), num_tiles, [&](SEAL_MAYBE_UNUSED auto J) {
                    // Compute third output polynomial, overwriting input
                    // x[2] = x[1] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_1_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_2_iter[0]);

                    // Compute second output polynomial, overwriting input
                    // temp = x[1] * y[0]
                    dyadic_product_coeffmod(encrypted1_1_iter[0], encrypted2_0_iter[0], tile_size, I, temp);
                    // x[1] = x[0] * y[1]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_1_iter[0], tile_size, I, encrypted1_1_iter[0]);
                    // x[1] += temp
                    add_poly_coeffmod(encrypted1_1_iter[0], temp, tile_size, I, encrypted1_1_iter[0]);

                    // Compute first output polynomial, overwriting input
                    // x[0] = x[0] * y[0]
                    dyadic_product_coeffmod(
                        encrypted1_0_iter[0], encrypted2_0_iter[0], tile_size, I, encrypted1_0_iter[0]);

                    // Manually increment iterators
                    encrypted1_0_iter++;
                    encrypted1_1_iter++;
                    encrypted1_2_iter++;
                    encrypted2_0_iter++;
                    encrypted2_1_iter++;
                });
            });
        }
        else
        {
            // Allocate temporary space for the result
            SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

            SEAL_ITERATE(iter(size_t(0)), dest_size, [&](auto I) {
                // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
                // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
                // the relevant terms are obtained as follows.
                size_t curr_encrypted1_last = min<size_t>(I, encrypted1_size - 1);
                size_t curr_encrypted2_first = min<size_t>(I, encrypted2_size - 1);
                size_t curr_encrypted1_first = I - curr_encrypted2_first;
                // size_t curr_encrypted2_last = secret_power_index - curr_encrypted1_last;

                // The total number of dyadic products is now easy to compute
                size_t steps = curr_encrypted1_last - curr_encrypted1_first + 1;

                // Create a shifted iterator for the first input
                auto shifted_encrypted1_iter = encrypted1_iter + curr_encrypted1_first;

                // Create a shifted reverse iterator for the second input
                auto shifted_reversed_encrypted2_iter = reverse_iter(encrypted2_iter + curr_encrypted2_first);

                SEAL_ITERATE(iter(shifted_encrypted1_iter, shifted_reversed_encrypted2_iter), steps, [&](auto J) {
                    // Extra care needed here:
                    // temp_iter must be dereferenced once to produce an appropriate RNSIter
                    SEAL_ITERATE(iter(J, coeff_modulus, temp[I]), coeff_modulus_size, [&](auto K) {
                        SEAL_ALLOCATE_GET_COEFF_ITER(prod, coeff_count, pool);
                        dyadic_product_coeffmod(get<0, 0>(K), get<0, 1>(K), coeff_count, get<1>(K), prod);
                        add_poly_coeffmod(prod, get<2>(K), coeff_count, get<1>(K), get<2>(K));
                    });
                });
            });

            // Set the final result
            set_poly_array(temp, dest_size, coeff_count, coeff_modulus_size, encrypted1.data());
        }

        // Set the correction factor
        encrypted1.correction_factor() =
            multiply_uint_mod(encrypted1.correction_factor(), encrypted2.correction_factor(), parms.plain_modulus());
    }

    void Evaluator::square_inplace(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.size() < SEAL_CIPHERTEXT_SIZE_MIN)
        {
            throw invalid_argument("encrypted must have size at least 2");
        }

        auto context_data_ptr = context_.first_context_data();
        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            bfv_square(encrypted, std::move(pool));
            break;

        case scheme_type::ckks:
            ckks_square(encrypted, std::move(pool));
            break;

        case scheme_type::bgv:
            bgv_square(encrypted, std::move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::bfv_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        // bfv_multiply recognizes squaring: BEHZ steps (1)-(3) are done only once, and the dyadic square needs only
        // about half of the products (three for a size-2 ciphertext)
        bfv_multiply(encrypted, encrypted, std::move(pool));
    }

    void Evaluator::ckks_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            ckks_multiply(encrypted, encrypted, std::move(pool));
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertext
        auto encrypted_iter = iter(encrypted);

        // Compute c1^2
        dyadic_product_coeffmod(
            encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[2]);

        // Compute 2*c0*c1
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);
        add_poly_coeffmod(encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);

        // Compute c0^2
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[0], coeff_modulus_size, coeff_modulus, encrypted_iter[0]);

        // Set the scale
        encrypted.scale() *= encrypted.scale();
        if (!is_scale_within_bounds(encrypted.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::bgv_square(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_size = encrypted.size();

        // Optimization implemented currently only for size 2 ciphertexts
        if (encrypted_size != 2)
        {
            bgv_multiply(encrypted, encrypted, std::move(pool));
            return;
        }

        // Determine destination.size()
        // Default is 3 (c_0, c_1, c_2)
        size_t dest_size = sub_safe(add_safe(encrypted_size, encrypted_size), size_t(1));

        // Size check
        if (!product_fits_in(dest_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Set up iterator for the base
        auto coeff_modulus = iter(parms.coeff_modulus());

        // Prepare destination
        encrypted.resize(context_, context_data.parms_id(), dest_size);

        // Set up iterators for input ciphertext
        auto encrypted_iter = iter(encrypted);

        // Allocate temporary space for the result
        SEAL_ALLOCATE_ZERO_GET_POLY_ITER(temp, dest_size, coeff_count, coeff_modulus_size, pool);

        // Compute c1^2
        dyadic_product_coeffmod(
            encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[2]);

        // Compute 2*c0*c1
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);
        add_poly_coeffmod(encrypted_iter[1], encrypted_iter[1], coeff_modulus_size, coeff_modulus, encrypted_iter[1]);

        // Compute c0^2
        dyadic_product_coeffmod(
            encrypted_iter[0], encrypted_iter[0], coeff_modulus_size, coeff_modulus, encrypted_iter[0]);

        // Set the correction factor
        encrypted.correction_factor() =
            multiply_uint_mod(encrypted.correction_factor(), encrypted.correction_factor(), parms.plain_modulus());
    }

    void Evaluator::relinearize_internal(
        Ciphertext &encrypted, const RelinKeys &relin_keys, size_t destination_size, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        // The key switching below does not validate the ciphertext, so check it here.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (relin_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }

        size_t encrypted_size = encrypted.size();

        // Verify parameters.
        if (destination_size < 2 || destination_size > encrypted_size)
        {
            throw invalid_argument("destination_size must be at least 2 and less than or equal to current count");
        }
        if (relin_keys.size() < sub_safe(encrypted_size, size_t(2)))
        {
            throw invalid_argument("not enough relinearization keys");
        }

        // If encrypted is already at the desired level, return
        if (destination_size == encrypted_size)
        {
            return;
        }

        // Calculate number of relinearize_one_step calls needed
        size_t relins_needed = encrypted_size - destination_size;

        // Verify the key switching parameters and keys before encrypted is modified
        auto &parms = context_data_ptr->parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t decomp_modulus_size = parms.coeff_modulus().size();
        if (!context_.using_keyswitching())
        {
            throw logic_error("keyswitching is not supported by the context");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        validate_ntt_form(encrypted, parms.scheme());
        if (!product_fits_in(coeff_count, decomp_modulus_size + 1, size_t(2)))
        {
            throw logic_error("invalid parameters");
        }
        for (size_t i = 0; i < relins_needed; i++)
        {
            validate_kswitch_key_vector(
                relin_keys.data(RelinKeys::get_index(encrypted_size - 1 - i)), decomp_modulus_size, context_);
        }

        // Step i key switches component encrypted_size - 1 - i, which multiplies the same power of the secret key, and
        // adds the result to the first two components
        uint64_t *outputs[2]{ encrypted.data(0), encrypted.data(1) };
        for (size_t i = 0; i < relins_needed; i++)
        {
            size_t key_power = encrypted_size - 1 - i;
            switch_key(
                encrypted.parms_id(), ConstRNSIter(encrypted.data(key_power), coeff_count),
                relin_keys.data(RelinKeys::get_index(key_power)), outputs, outputs, pool);
        }

        // Put the output of final relinearization into destination.
        // Prepare destination only at this point because we are resizing down
        encrypted.resize(context_, context_data_ptr->parms_id(), destination_size);
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::mod_switch_scale_to_next(
        const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::bfv && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::ckks && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::bgv && !encrypted.is_ntt_form())
        {
            throw invalid_argument("BGV encrypted must be in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &next_context_data = *context_data.next_context_data();
        auto &next_parms = next_context_data.parms();
        auto rns_tool = context_data.rns_tool();

        double destination_scale = 1.0;
        if (next_parms.scheme() == scheme_type::ckks)
        {
            if (!is_scale_within_bounds(encrypted.scale(), context_data))
            {
                throw invalid_argument("scale out of bounds");
            }
            destination_scale =
                encrypted.scale() / static_cast<double>(context_data.parms().coeff_modulus().back().value());
            if (!is_scale_within_bounds(destination_scale, next_context_data))
            {
                throw invalid_argument("scale out of bounds");
            }
        }

        size_t encrypted_size = encrypted.size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        auto scheme = next_parms.scheme();
        if (scheme != scheme_type::bfv && scheme != scheme_type::ckks && scheme != scheme_type::bgv)
        {
            throw invalid_argument("unsupported scheme");
        }

        // When switching in place, the result is computed in new memory from the pool of destination, so that
        // encrypted is unchanged if an exception is thrown
        bool in_place = (&encrypted == &destination);
        Ciphertext temp(destination.pool());
        Ciphertext &result = in_place ? temp : destination;
        result.resize(context_, next_context_data.parms_id(), encrypted_size);

        // Divide each polynomial by the last modulus
        for (size_t i = 0; i < encrypted_size; i++)
        {
            ConstRNSIter input(encrypted.data(i), coeff_count);
            RNSIter output(result.data(i), coeff_count);
            switch (scheme)
            {
            case scheme_type::bfv:
                rns_tool->divide_and_round_q_last(input, output, pool);
                break;

            case scheme_type::ckks:
                rns_tool->divide_and_round_q_last_ntt(input, context_data.small_ntt_tables(), output, pool);
                break;

            default: // scheme_type::bgv
                rns_tool->mod_t_and_divide_q_last_ntt(input, context_data.small_ntt_tables(), output, pool);
                break;
            }
        }

        // Set other attributes
        result.is_ntt_form() = encrypted.is_ntt_form();
        if (scheme == scheme_type::ckks)
        {
            // Change the scale when using CKKS
            result.scale() = destination_scale;
        }
        else if (scheme == scheme_type::bgv)
        {
            // Change the correction factor when using BGV
            result.correction_factor() = multiply_uint_mod(
                encrypted.correction_factor(), rns_tool->inv_q_last_mod_t(), next_parms.plain_modulus());
        }

        if (in_place)
        {
            destination = std::move(temp);
        }
    }

    void Evaluator::mod_switch_drop_to_next(const Ciphertext &encrypted, Ciphertext &destination) const
    {
        // Assuming at this point encrypted is already validated.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_data_ptr->parms().scheme() == scheme_type::bfv && encrypted.is_ntt_form())
        {
            throw invalid_argument("BFV encrypted cannot be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::ckks && !encrypted.is_ntt_form())
        {
            throw invalid_argument("CKKS encrypted must be in NTT form");
        }
        if (context_data_ptr->parms().scheme() == scheme_type::bgv && !encrypted.is_ntt_form())
        {
            throw invalid_argument("BGV encrypted must be in NTT form");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = next_context_data.parms();

        if (!is_scale_within_bounds(encrypted.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        size_t next_coeff_modulus_size = next_parms.coeff_modulus().size();
        size_t coeff_count = next_parms.poly_modulus_degree();
        size_t encrypted_size = encrypted.size();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, next_coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        auto drop_modulus_and_copy = [&](ConstPolyIter in_iter, PolyIter out_iter) {
            SEAL_ITERATE(iter(in_iter, out_iter), encrypted_size, [&](auto I) {
                SEAL_ITERATE(
                    iter(I), next_coeff_modulus_size, [&](auto J) { set_uint(get<0>(J), coeff_count, get<1>(J)); });
            });
        };

        if (&encrypted == &destination)
        {
            // Switching in place: move the RNS components that remain after the modulus drop to their positions in
            // the layout of the next level. Polynomial 0 stays where it is, and every other polynomial moves to lower
            // addresses (possibly overlapping its old position), so no data that is still needed is overwritten and no
            // temporary space is needed.
            size_t coeff_modulus_size = context_data_ptr->parms().coeff_modulus().size();
            PolyIter in_iter(destination.data(), coeff_count, coeff_modulus_size);
            PolyIter out_iter(destination.data(), coeff_count, next_coeff_modulus_size);
            for (size_t i = 1; i < encrypted_size; i++)
            {
                memmove(out_iter[i], in_iter[i], next_coeff_modulus_size * coeff_count * sizeof(uint64_t));
            }

            // Shrinking keeps the data
            destination.resize(context_, next_context_data.parms_id(), encrypted_size);
        }
        else
        {
            // Resize destination before writing
            destination.resize(context_, next_context_data.parms_id(), encrypted_size);

            // Copy data over to destination; only copy the RNS components relevant after modulus drop
            drop_modulus_and_copy(encrypted, destination);
        }
        destination.is_ntt_form() = encrypted.is_ntt_form();
        destination.scale() = encrypted.scale();
        destination.correction_factor() = encrypted.correction_factor();
    }

    void Evaluator::mod_switch_drop_to_next(Plaintext &plain) const
    {
        // Assuming at this point plain is already validated.
        auto context_data_ptr = context_.get_context_data(plain.parms_id());
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (!context_data_ptr->next_context_data())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }

        // Extract encryption parameters.
        auto &next_context_data = *context_data_ptr->next_context_data();
        auto &next_parms = context_data_ptr->next_context_data()->parms();

        if (!is_scale_within_bounds(plain.scale(), next_context_data))
        {
            throw invalid_argument("scale out of bounds");
        }

        // q_1,...,q_{k-1}
        auto &next_coeff_modulus = next_parms.coeff_modulus();
        size_t next_coeff_modulus_size = next_coeff_modulus.size();
        size_t coeff_count = next_parms.poly_modulus_degree();

        // Compute destination size first for exception safety
        auto dest_size = mul_safe(next_coeff_modulus_size, coeff_count);

        plain.parms_id() = parms_id_zero;
        plain.resize(dest_size);
        plain.parms_id() = next_context_data.parms_id();
    }

    void Evaluator::mod_switch_to_next(
        const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_.first_context_data()->parms().scheme())
        {
        case scheme_type::bfv:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, std::move(pool));
            break;

        case scheme_type::ckks:
            // Modulus switching without scaling
            mod_switch_drop_to_next(encrypted, destination);
            break;

        case scheme_type::bgv:
            mod_switch_scale_to_next(encrypted, destination, std::move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (destination.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::mod_switch_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters. The loop below performs no iterations when encrypted is already at
        // the target level, so validate it here rather than relying on mod_switch_to_next_inplace.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(encrypted, pool);
        }
    }

    void Evaluator::mod_switch_to_inplace(Plaintext &plain, parms_id_type parms_id) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(plain.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!context_.get_context_data(parms_id))
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (!plain.is_ntt_form())
        {
            throw invalid_argument("plain is not in NTT form");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (plain.parms_id() != parms_id)
        {
            mod_switch_to_next_inplace(plain);
        }
    }

    void Evaluator::rescale_to_next(const Ciphertext &encrypted, Ciphertext &destination, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_.first_context_data()->parms().scheme())
        {
        case scheme_type::bfv:
            /* Fall through */
        case scheme_type::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::ckks:
            // Modulus switching with scaling
            mod_switch_scale_to_next(encrypted, destination, std::move(pool));
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (destination.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::rescale_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        switch (context_data_ptr->parms().scheme())
        {
        case scheme_type::bfv:
            /* Fall through */
        case scheme_type::bgv:
            throw invalid_argument("unsupported operation for scheme type");

        case scheme_type::ckks:
            while (encrypted.parms_id() != parms_id)
            {
                // Modulus switching with scaling
                mod_switch_scale_to_next(encrypted, encrypted, pool);
            }
            break;

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::mod_reduce_to_next_inplace(Ciphertext &encrypted, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (context_.last_parms_id() == encrypted.parms_id())
        {
            throw invalid_argument("end of modulus switching chain reached");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        mod_switch_drop_to_next(encrypted, encrypted);
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::mod_reduce_to_inplace(Ciphertext &encrypted, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters. The loop below performs no iterations when encrypted is already at
        // the target level, so validate it here rather than relying on mod_reduce_to_next_inplace.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        auto target_context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!target_context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for encryption parameters");
        }
        if (context_data_ptr->chain_index() < target_context_data_ptr->chain_index())
        {
            throw invalid_argument("cannot switch to higher level modulus");
        }

        while (encrypted.parms_id() != parms_id)
        {
            mod_reduce_to_next_inplace(encrypted, pool);
        }
    }

    void Evaluator::multiply_many(
        const vector<Ciphertext> &encrypteds, const RelinKeys &relin_keys, Ciphertext &destination,
        MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (encrypteds.size() == 0)
        {
            throw invalid_argument("encrypteds vector must not be empty");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        for (size_t i = 0; i < encrypteds.size(); i++)
        {
            if (&encrypteds[i] == &destination)
            {
                throw invalid_argument("encrypteds must be different from destination");
            }
        }

        // There is at least one ciphertext
        auto context_data_ptr = context_.get_context_data(encrypteds[0].parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // The single-ciphertext path below returns without reaching multiply, which is what
        // would otherwise validate the inputs, so check them here.
        if (!is_metadata_valid_for(encrypteds[0], context_) || !is_buffer_valid(encrypteds[0]))
        {
            throw invalid_argument("encrypteds is not valid for encryption parameters");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();

        if (parms.scheme() != scheme_type::bfv && parms.scheme() != scheme_type::bgv)
        {
            throw logic_error("unsupported scheme");
        }

        // If there is only one ciphertext, return it.
        if (encrypteds.size() == 1)
        {
            destination = encrypteds[0];
            return;
        }

        // Do first level of multiplications
        vector<Ciphertext> product_vec;
        for (size_t i = 0; i < encrypteds.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parms_id(), pool);
            if (encrypteds[i].data() == encrypteds[i + 1].data())
            {
                square(encrypteds[i], temp);
            }
            else
            {
                multiply(encrypteds[i], encrypteds[i + 1], temp);
            }
            relinearize_inplace(temp, relin_keys, pool);
            product_vec.emplace_back(std::move(temp));
        }
        if (encrypteds.size() & 1)
        {
            product_vec.emplace_back(encrypteds.back());
        }

        // Repeatedly multiply and add to the back of the vector until the end is reached
        for (size_t i = 0; i < product_vec.size() - 1; i += 2)
        {
            Ciphertext temp(context_, context_data.parms_id(), pool);
            multiply(product_vec[i], product_vec[i + 1], temp);
            relinearize_inplace(temp, relin_keys, pool);
            product_vec.emplace_back(std::move(temp));
        }

        destination = product_vec.back();
    }

    void Evaluator::exponentiate_inplace(
        Ciphertext &encrypted, uint64_t exponent, const RelinKeys &relin_keys, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        // The exponent == 1 path below returns without reaching multiply_many, which is what
        // would otherwise validate the ciphertext, so check it here.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_.get_context_data(relin_keys.parms_id()))
        {
            throw invalid_argument("relin_keys is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }
        if (exponent == 0)
        {
            throw invalid_argument("exponent cannot be 0");
        }

        // Fast case
        if (exponent == 1)
        {
            return;
        }

        // Create a vector of copies of encrypted
        vector<Ciphertext> exp_vector(static_cast<size_t>(exponent), encrypted);
        multiply_many(exp_vector, relin_keys, encrypted, std::move(pool));
    }

    void Evaluator::add_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::bfv)
        {
            if (encrypted.is_ntt_form())
            {
                throw invalid_argument("BFV encrypted cannot be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BFV plain cannot be in NTT form");
            }
        }
        else if (parms.scheme() == scheme_type::ckks)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("CKKS encrypted must be in NTT form");
            }
            if (!plain.is_ntt_form())
            {
                throw invalid_argument("CKKS plain must be in NTT form");
            }
            if (encrypted.parms_id() != plain.parms_id())
            {
                throw invalid_argument("encrypted and plain parameter mismatch");
            }
            if (!are_same_scale(encrypted, plain))
            {
                throw invalid_argument("scale mismatch");
            }
        }
        else if (parms.scheme() == scheme_type::bgv)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("BGV encrypted must be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BGV plain cannot be in NTT form");
            }
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::bfv:
        {
            multiply_add_plain_with_scaling_variant(plain, context_data, *iter(encrypted));
            break;
        }

        case scheme_type::ckks:
        {
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain.data(), coeff_count);
            add_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        case scheme_type::bgv:
        {
            Plaintext plain_copy = plain;
            multiply_poly_scalar_coeffmod(
                plain.data(), plain.coeff_count(), encrypted.correction_factor(), parms.plain_modulus(),
                plain_copy.data());
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), std::move(pool));
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain_copy.data(), coeff_count);
            add_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::sub_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        if (parms.scheme() == scheme_type::bfv)
        {
            if (encrypted.is_ntt_form())
            {
                throw invalid_argument("BFV encrypted cannot be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BFV plain cannot be in NTT form");
            }
        }
        else if (parms.scheme() == scheme_type::ckks)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("CKKS encrypted must be in NTT form");
            }
            if (!plain.is_ntt_form())
            {
                throw invalid_argument("CKKS plain must be in NTT form");
            }
            if (encrypted.parms_id() != plain.parms_id())
            {
                throw invalid_argument("encrypted and plain parameter mismatch");
            }
            if (!are_same_scale(encrypted, plain))
            {
                throw invalid_argument("scale mismatch");
            }
        }
        else if (parms.scheme() == scheme_type::bgv)
        {
            if (!encrypted.is_ntt_form())
            {
                throw invalid_argument("BGV encrypted must be in NTT form");
            }
            if (plain.is_ntt_form())
            {
                throw invalid_argument("BGV plain cannot be in NTT form");
            }
        }

        // Extract encryption parameters.
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        switch (parms.scheme())
        {
        case scheme_type::bfv:
        {
            multiply_sub_plain_with_scaling_variant(plain, context_data, *iter(encrypted));
            break;
        }

        case scheme_type::ckks:
        {
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain.data(), coeff_count);
            sub_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        case scheme_type::bgv:
        {
            Plaintext plain_copy = plain;
            multiply_poly_scalar_coeffmod(
                plain.data(), plain.coeff_count(), encrypted.correction_factor(), parms.plain_modulus(),
                plain_copy.data());
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), std::move(pool));
            RNSIter encrypted_iter(encrypted.data(), coeff_count);
            ConstRNSIter plain_iter(plain_copy.data(), coeff_count);
            sub_poly_coeffmod(encrypted_iter, plain_iter, coeff_modulus_size, coeff_modulus, encrypted_iter);
            break;
        }

        default:
            throw invalid_argument("unsupported scheme");
        }
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_plain_inplace(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!is_metadata_valid_for(plain, context_) || !is_buffer_valid(plain))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        if (encrypted.is_ntt_form() && plain.is_ntt_form())
        {
            multiply_plain_ntt(encrypted, plain);
        }
        else if (!encrypted.is_ntt_form() && !plain.is_ntt_form())
        {
            multiply_plain_normal(encrypted, plain, std::move(pool));
        }
        else if (encrypted.is_ntt_form() && !plain.is_ntt_form())
        {
            Plaintext plain_copy = plain;
            transform_to_ntt_inplace(plain_copy, encrypted.parms_id(), std::move(pool));
            multiply_plain_ntt(encrypted, plain_copy);
        }
        else
        {
            // multiply_plain_ntt below requires a matching parms_id, but the transform mutates
            // encrypted, so verify the match before that rather than after.
            if (encrypted.parms_id() != plain.parms_id())
            {
                throw invalid_argument("encrypted and plain parameter mismatch");
            }
            transform_to_ntt_inplace(encrypted);
            multiply_plain_ntt(encrypted, plain);
            transform_from_ntt_inplace(encrypted);
        }

#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::multiply_plain_normal(Ciphertext &encrypted, const Plaintext &plain, MemoryPoolHandle pool) const
    {
        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();
        auto ntt_tables = iter(context_data.small_ntt_tables());

        size_t encrypted_size = encrypted.size();
        size_t plain_coeff_count = plain.coeff_count();
        size_t plain_nonzero_coeff_count = plain.nonzero_coeff_count();

        // Size check
        if (!product_fits_in(encrypted_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        /*
        Optimizations for constant / monomial multiplication can lead to the presence of a timing side-channel in
        use-cases where the plaintext data should also be kept private.
        */
        if (plain_nonzero_coeff_count == 1)
        {
            // Multiplying by a monomial?
            size_t mono_exponent = plain.significant_coeff_count() - 1;

            if (plain[mono_exponent] >= plain_upper_half_threshold)
            {
                if (!context_data.qualifiers().using_fast_plain_lift)
                {
                    // Allocate temporary space for a single RNS coefficient
                    SEAL_ALLOCATE_GET_COEFF_ITER(temp, coeff_modulus_size, pool);

                    // We need to adjust the monomial modulo each coeff_modulus prime separately when the coeff_modulus
                    // primes may be larger than the plain_modulus. We add plain_upper_half_increment (i.e., q-t) to
                    // the monomial to ensure it is smaller than coeff_modulus and then do an RNS multiplication. Note
                    // that in this case plain_upper_half_increment contains a multi-precision integer, so after the
                    // addition we decompose the multi-precision integer into RNS components, and then multiply.
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain[mono_exponent], temp);
                    context_data.rns_tool()->base_q()->decompose(temp, pool);
                    negacyclic_multiply_poly_mono_coeffmod(
                        encrypted, encrypted_size, temp, mono_exponent, coeff_modulus, encrypted, pool);
                }
                else
                {
                    // Every coeff_modulus prime is larger than plain_modulus, so there is no need to adjust the
                    // monomial. Instead, just do an RNS multiplication.
                    negacyclic_multiply_poly_mono_coeffmod(
                        encrypted, encrypted_size, plain[mono_exponent], mono_exponent, coeff_modulus, encrypted, pool);
                }
            }
            else
            {
                // The monomial represents a positive number, so no RNS multiplication is needed.
                negacyclic_multiply_poly_mono_coeffmod(
                    encrypted, encrypted_size, plain[mono_exponent], mono_exponent, coeff_modulus, encrypted, pool);
            }

            // Set the scale
            if (parms.scheme() == scheme_type::ckks)
            {
                encrypted.scale() *= plain.scale();
                if (!is_scale_within_bounds(encrypted.scale(), context_data))
                {
                    throw invalid_argument("scale out of bounds");
                }
            }

            return;
        }

        // Generic case: any plaintext polynomial
        // Allocate temporary space for an entire RNS polynomial
        auto temp(allocate_zero_poly(coeff_count, coeff_modulus_size, pool));

        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            StrideIter<uint64_t *> temp_iter(temp.get(), coeff_modulus_size);

            SEAL_ITERATE(iter(plain.data(), temp_iter), plain_coeff_count, [&](auto I) {
                auto plain_value = get<0>(I);
                if (plain_value >= plain_upper_half_threshold)
                {
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain_value, get<1>(I));
                }
                else
                {
                    *get<1>(I) = plain_value;
                }
            });

            context_data.rns_tool()->base_q()->decompose_array(temp_iter, coeff_count, pool);
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            RNSIter temp_iter(temp.get(), coeff_count);
            SEAL_ITERATE(iter(temp_iter, plain_upper_half_increment), coeff_modulus_size, [&](auto I) {
                SEAL_ITERATE(iter(get<0>(I), plain.data()), plain_coeff_count, [&](auto J) {
                    get<0>(J) =
                        SEAL_COND_SELECT(get<1>(J) >= plain_upper_half_threshold, get<1>(J) + get<1>(I), get<1>(J));
                });
            });
        }

        // Need to multiply each component in encrypted with temp; first step is to transform to NTT form
        RNSIter temp_iter(temp.get(), coeff_count);
        ntt_negacyclic_harvey(temp_iter, coeff_modulus_size, ntt_tables);

        SEAL_ITERATE(iter(encrypted), encrypted_size, [&](auto I) {
            SEAL_ITERATE(iter(I, temp_iter, coeff_modulus, ntt_tables), coeff_modulus_size, [&](auto J) {
                // Lazy reduction
                ntt_negacyclic_harvey_lazy(get<0>(J), get<3>(J));
#ifdef SEAL_USE_INTEL_HEXL
                dyadic_product_coeffmod(get<0>(J), get<1>(J), coeff_count, get<2>(J), get<0>(J));
                inverse_ntt_negacyclic_harvey(get<0>(J), get<3>(J));
#else
                // Dyadic product with Montgomery reduction, giving x * y * 2^(-64) mod p: the inputs are in [0, 4p)
                // (lazy NTT output) and [0, p) (fully reduced NTT), so the product is below 4p^2 < p * 2^64. The
                // factor 2^64 is folded into the scalar of the inverse NTT, whose output is fully reduced.
                const DyadicMontgomeryReducer reducer(get<2>(J));
                uint64_t *x = get<0>(J);
                const uint64_t *y = get<1>(J);
                for (size_t l = 0; l < coeff_count; l++)
                {
                    unsigned long long prod[2];
                    multiply_uint64(x[l], y[l], prod);
                    x[l] = reducer.reduce(prod[0], prod[1]);
                }
                inverse_ntt_negacyclic_harvey_scaled(get<0>(J), two_pow_64_mod(get<2>(J)), get<3>(J), get<0>(J));
#endif
            });
        });

        // Set the scale
        if (parms.scheme() == scheme_type::ckks)
        {
            encrypted.scale() *= plain.scale();
            if (!is_scale_within_bounds(encrypted.scale(), context_data))
            {
                throw invalid_argument("scale out of bounds");
            }
        }
    }

    void Evaluator::multiply_plain_ntt(Ciphertext &encrypted_ntt, const Plaintext &plain_ntt) const
    {
        // Verify parameters.
        if (!plain_ntt.is_ntt_form())
        {
            throw invalid_argument("plain_ntt is not in NTT form");
        }
        if (encrypted_ntt.parms_id() != plain_ntt.parms_id())
        {
            throw invalid_argument("encrypted_ntt and plain_ntt parameter mismatch");
        }

        // Extract encryption parameters.
        auto &context_data = *context_.get_context_data(encrypted_ntt.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        // Size check
        if (!product_fits_in(encrypted_ntt_size, coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

#ifdef SEAL_USE_INTEL_HEXL
        // Intel HEXL's dyadic product has no faster form for a shared operand, so multiply each ciphertext component
        ConstRNSIter plain_ntt_iter(plain_ntt.data(), coeff_count);
        SEAL_ITERATE(iter(encrypted_ntt), encrypted_ntt_size, [&](auto I) {
            dyadic_product_coeffmod(I, plain_ntt_iter, coeff_modulus_size, coeff_modulus, I);
        });
#else
        // Multiply the ciphertext components by the plaintext, one RNS component at a time. Pairs of ciphertext
        // components share the plaintext operand, which dyadic_product_shared_coeffmod requires to be reduced. The
        // plaintext data is not validated (e.g., after unsafe_load), so an unreduced component falls back to separate
        // dyadic products.
        SEAL_ITERATE(iter(coeff_modulus, size_t(0)), coeff_modulus_size, [&](auto I) {
            const Modulus &modulus = get<0>(I);
            const size_t offset = get<1>(I) * coeff_count;
            ConstCoeffIter plain(plain_ntt.data() + offset);

            size_t poly_index = 0;
            if (!any_value_at_least(plain_ntt.data() + offset, coeff_count, modulus.value()))
            {
                for (; poly_index + 2 <= encrypted_ntt_size; poly_index += 2)
                {
                    CoeffIter c0(encrypted_ntt.data(poly_index) + offset);
                    CoeffIter c1(encrypted_ntt.data(poly_index + 1) + offset);
                    dyadic_product_shared_coeffmod(c0, c1, plain, coeff_count, modulus, c0, c1);
                }
            }
            for (; poly_index < encrypted_ntt_size; poly_index++)
            {
                CoeffIter c(encrypted_ntt.data(poly_index) + offset);
                dyadic_product_coeffmod(c, plain, coeff_count, modulus, c);
            }
        });
#endif

        // Set the scale
        encrypted_ntt.scale() *= plain_ntt.scale();
        if (!is_scale_within_bounds(encrypted_ntt.scale(), context_data))
        {
            throw invalid_argument("scale out of bounds");
        }
    }

    void Evaluator::transform_to_ntt_inplace(Plaintext &plain, parms_id_type parms_id, MemoryPoolHandle pool) const
    {
        // Verify parameters.
        if (!is_valid_for(plain, context_))
        {
            throw invalid_argument("plain is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(parms_id);
        if (!context_data_ptr)
        {
            throw invalid_argument("parms_id is not valid for the current context");
        }
        if (plain.is_ntt_form())
        {
            throw invalid_argument("plain is already in NTT form");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t plain_coeff_count = plain.coeff_count();

        uint64_t plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        auto plain_upper_half_increment = context_data.plain_upper_half_increment();

        auto ntt_tables = iter(context_data.small_ntt_tables());

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Resize to fit the entire NTT transformed (ciphertext size) polynomial
        // Note that the new coefficients are automatically set to 0
        plain.resize(coeff_count * coeff_modulus_size);
        RNSIter plain_iter(plain.data(), coeff_count);

        if (!context_data.qualifiers().using_fast_plain_lift)
        {
            // Allocate temporary space for an entire RNS polynomial
            // Slight semantic misuse of RNSIter here, but this works well
            SEAL_ALLOCATE_ZERO_GET_RNS_ITER(temp, coeff_modulus_size, coeff_count, pool);

            SEAL_ITERATE(iter(plain.data(), temp), plain_coeff_count, [&](auto I) {
                auto plain_value = get<0>(I);
                if (plain_value >= plain_upper_half_threshold)
                {
                    add_uint(plain_upper_half_increment, coeff_modulus_size, plain_value, get<1>(I));
                }
                else
                {
                    *get<1>(I) = plain_value;
                }
            });

            context_data.rns_tool()->base_q()->decompose_array(temp, coeff_count, pool);

            // Copy data back to plain
            set_poly(temp, coeff_count, coeff_modulus_size, plain.data());
        }
        else
        {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.

            // Create a "reversed" helper iterator that iterates in the reverse order both plain RNS components and
            // the plain_upper_half_increment values.
            auto helper_iter = reverse_iter(plain_iter, plain_upper_half_increment);
            advance(helper_iter, -safe_cast<ptrdiff_t>(coeff_modulus_size - 1));

            SEAL_ITERATE(helper_iter, coeff_modulus_size, [&](auto I) {
                SEAL_ITERATE(iter(*plain_iter, get<0>(I)), plain_coeff_count, [&](auto J) {
                    get<1>(J) =
                        SEAL_COND_SELECT(get<0>(J) >= plain_upper_half_threshold, get<0>(J) + get<1>(I), get<0>(J));
                });
            });
        }

        // Transform to NTT domain
        ntt_negacyclic_harvey(plain_iter, coeff_modulus_size, ntt_tables);

        plain.parms_id() = parms_id;
    }

    void Evaluator::transform_to_ntt_inplace(Ciphertext &encrypted) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted, context_) || !is_buffer_valid(encrypted))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted is already in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        size_t encrypted_size = encrypted.size();

        auto ntt_tables = iter(context_data.small_ntt_tables());

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial to NTT domain
        ntt_negacyclic_harvey(encrypted, encrypted_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted.is_ntt_form() = true;
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::transform_from_ntt_inplace(Ciphertext &encrypted_ntt) const
    {
        // Verify parameters.
        if (!is_metadata_valid_for(encrypted_ntt, context_) || !is_buffer_valid(encrypted_ntt))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto context_data_ptr = context_.get_context_data(encrypted_ntt.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted_ntt is not valid for encryption parameters");
        }
        if (!encrypted_ntt.is_ntt_form())
        {
            throw invalid_argument("encrypted_ntt is not in NTT form");
        }

        // Extract encryption parameters.
        auto &context_data = *context_data_ptr;
        auto &parms = context_data.parms();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = parms.coeff_modulus().size();
        size_t encrypted_ntt_size = encrypted_ntt.size();

        auto ntt_tables = iter(context_data.small_ntt_tables());

        // Size check
        if (!product_fits_in(coeff_count, coeff_modulus_size))
        {
            throw logic_error("invalid parameters");
        }

        // Transform each polynomial from NTT domain
        inverse_ntt_negacyclic_harvey(encrypted_ntt, encrypted_ntt_size, ntt_tables);

        // Finally change the is_ntt_transformed flag
        encrypted_ntt.is_ntt_form() = false;
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted_ntt.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::apply_galois_inplace(
        Ciphertext &encrypted, uint32_t galois_elt, const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
    {
        // Verify parameters; encrypted is not modified before all checks have passed
        validate_galois(context_, encrypted, galois_elt, galois_keys);

        auto &context_data = *context_.get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_modulus_size = coeff_modulus.size();
        // Use key_context_data where permutation tables exist since previous runs.
        auto galois_tool = context_.key_context_data()->galois_tool();

        SEAL_ALLOCATE_GET_RNS_ITER(temp, coeff_count, coeff_modulus_size, pool);

        // Apply the Galois automorphism to both polynomials without copies: galois(c1), the key-switching target,
        // goes to temp first; c1 is then free and receives galois(c0). The key switching adds its first component to
        // galois(c0) (read from c1) and writes the sum to c0, and then writes its second component to c1.
        // Execution order is sensitive, since apply_galois is not in place.
        auto encrypted_iter = iter(encrypted);
        if (parms.scheme() == scheme_type::bfv)
        {
            galois_tool->apply_galois(encrypted_iter[1], coeff_modulus_size, galois_elt, coeff_modulus, temp);
            galois_tool->apply_galois(
                encrypted_iter[0], coeff_modulus_size, galois_elt, coeff_modulus, encrypted_iter[1]);
        }
        else if (parms.scheme() == scheme_type::ckks || parms.scheme() == scheme_type::bgv)
        {
            galois_tool->apply_galois_ntt(encrypted_iter[1], coeff_modulus_size, galois_elt, temp);
            galois_tool->apply_galois_ntt(encrypted_iter[0], coeff_modulus_size, galois_elt, encrypted_iter[1]);
        }
        else
        {
            throw logic_error("scheme not implemented");
        }

        // Calculate (temp * galois_key[0], temp * galois_key[1]) + (galois(ct[0]), 0)
        const uint64_t *addends[2]{ encrypted.data(1), nullptr };
        uint64_t *outputs[2]{ encrypted.data(0), encrypted.data(1) };
        switch_key(
            encrypted.parms_id(), temp, galois_keys.data(GaloisKeys::get_index(galois_elt)), addends, outputs,
            std::move(pool));
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
        // Transparent ciphertext output is not allowed.
        if (encrypted.is_transparent())
        {
            throw logic_error("result ciphertext is transparent");
        }
#endif
    }

    void Evaluator::rotate_internal(
        Ciphertext &encrypted, int steps, const GaloisKeys &galois_keys, MemoryPoolHandle pool) const
    {
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_data_ptr->qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }
        if (galois_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }

        // Is there anything to do?
        if (steps == 0)
        {
            return;
        }

        size_t coeff_count = context_data_ptr->parms().poly_modulus_degree();
        auto galois_tool = context_data_ptr->galois_tool();

        // Check if Galois key is generated or not.
        if (galois_keys.has_key(galois_tool->get_elt_from_step(steps)))
        {
            // Perform rotation and key switching
            apply_galois_inplace(encrypted, galois_tool->get_elt_from_step(steps), galois_keys, std::move(pool));
        }
        else
        {
            // Convert the steps to NAF: guarantees using smallest HW
            vector<int> naf_steps = naf(steps);

            // If naf_steps contains only one element, then this is a power-of-two
            // rotation and we would have expected not to get to this part of the
            // if-statement.
            if (naf_steps.size() == 1)
            {
                throw invalid_argument("Galois key not present");
            }

            SEAL_ITERATE(naf_steps.cbegin(), naf_steps.size(), [&](auto step) {
                // We might have a NAF-term of size coeff_count / 2; this corresponds
                // to no rotation so we skip it. Otherwise call rotate_internal.
                if (safe_cast<size_t>(abs(step)) != (coeff_count >> 1))
                {
                    // Apply rotation for this step
                    this->rotate_internal(encrypted, step, galois_keys, pool);
                }
            });
        }
    }

    namespace
    {
        // Key switching keys are public keys, which have two components
        constexpr size_t kswitch_key_component_count = 2;

        // Number of products a * b with a < 4q and b < q (q has at most SEAL_USER_MOD_BIT_COUNT_MAX bits) that can be
        // added to a 128-bit accumulator holding a value less than q without overflow. With 60-bit moduli this is 63.
        constexpr size_t kswitch_lazy_summand_bound =
            (static_cast<size_t>(SEAL_MULTIPLY_ACCUMULATE_USER_MOD_MAX) >> 2) - 1;
        static_assert(kswitch_lazy_summand_bound >= 2, "kswitch_lazy_summand_bound is too small");

        // Number of coefficients processed at a time by kswitch_dot_product; the 128-bit accumulators for one block of
        // two key components (16 KB) fit in L1 cache
        constexpr size_t kswitch_block_size = 512;

        // Number of words needed for the accumulators of kswitch_dot_product: two per coefficient and key component
        constexpr size_t kswitch_acc_scratch_size = 2 * kswitch_key_component_count * kswitch_block_size;

        // Computes for both key components k the fully reduced dot products
        //     out[k][l] = (sum_{j < digit_count} x_j[l] * keys[2 * j + k][l]) mod modulus,  l < coeff_count,
        // where x_j[l] = digits[j][l] or, with ApplyPermutation, x_j[l] = digits[j][perm[l]] + corrections[j][l]; the
        // latter applies a Galois automorphism to hoisted NTT-form digits. Requires x_j[l] < 4 * modulus and
        // keys[..][l] < modulus. acc_scratch must hold kswitch_acc_scratch_size words.
        template <bool ApplyPermutation>
        void kswitch_dot_product(
            size_t coeff_count, size_t digit_count, const uint64_t *const *digits, const uint32_t *perm,
            const uint64_t *const *corrections, const uint64_t *const *keys, const Modulus &modulus,
            uint64_t *const *out, unsigned long long *acc_scratch)
        {
            unsigned long long *acc[kswitch_key_component_count];
            for (size_t k = 0; k < kswitch_key_component_count; k++)
            {
                acc[k] = acc_scratch + 2 * k * kswitch_block_size;
            }

            // Constants for the Barrett reductions
            const uint64_t mod_value = modulus.value();
            const uint64_t two_pow_64_mod_value = two_pow_64_mod(modulus);
            const uint64_t const_ratio_0 = modulus.const_ratio()[0];
            const uint64_t const_ratio_1 = modulus.const_ratio()[1];

            for (size_t l0 = 0; l0 < coeff_count; l0 += kswitch_block_size)
            {
                const size_t block_size = min(kswitch_block_size, coeff_count - l0);
                for (size_t k = 0; k < kswitch_key_component_count; k++)
                {
                    fill_n(acc[k], 2 * block_size, 0ULL);
                }

                // Without ApplyPermutation the digits are read at the block offset; with it, they are read through the
                // block's entries of the permutation table
                const size_t digit_offset = ApplyPermutation ? 0 : l0;
                const uint32_t *p = ApplyPermutation ? perm + l0 : nullptr;

                for (size_t j = 0; j < digit_count;)
                {
                    // At most kswitch_lazy_summand_bound products are accumulated between reductions
                    const size_t j_end = min(digit_count, j + kswitch_lazy_summand_bound);

                    // Two digits at a time
                    for (; j + 2 <= j_end; j += 2)
                    {
                        const uint64_t *d0 = digits[j] + digit_offset;
                        const uint64_t *d1 = digits[j + 1] + digit_offset;
                        const uint64_t *f0 = ApplyPermutation ? corrections[j] + l0 : nullptr;
                        const uint64_t *f1 = ApplyPermutation ? corrections[j + 1] + l0 : nullptr;
                        const uint64_t *b0[kswitch_key_component_count];
                        const uint64_t *b1[kswitch_key_component_count];
                        for (size_t k = 0; k < kswitch_key_component_count; k++)
                        {
                            b0[k] = keys[j * kswitch_key_component_count + k] + l0;
                            b1[k] = keys[(j + 1) * kswitch_key_component_count + k] + l0;
                        }
                        for (size_t l = 0; l < block_size; l++)
                        {
                            const uint64_t x0 = ApplyPermutation ? d0[p[l]] + f0[l] : d0[l];
                            const uint64_t x1 = ApplyPermutation ? d1[p[l]] + f1[l] : d1[l];
                            for (size_t k = 0; k < kswitch_key_component_count; k++)
                            {
                                multiply_add_uint64(x0, b0[k][l], x1, b1[k][l], acc[k] + 2 * l);
                            }
                        }
                    }

                    // Remaining single digit
                    if (j < j_end)
                    {
                        const uint64_t *d0 = digits[j] + digit_offset;
                        const uint64_t *f0 = ApplyPermutation ? corrections[j] + l0 : nullptr;
                        const uint64_t *b0[kswitch_key_component_count];
                        for (size_t k = 0; k < kswitch_key_component_count; k++)
                        {
                            b0[k] = keys[j * kswitch_key_component_count + k] + l0;
                        }
                        for (size_t l = 0; l < block_size; l++)
                        {
                            const uint64_t x0 = ApplyPermutation ? d0[p[l]] + f0[l] : d0[l];
                            for (size_t k = 0; k < kswitch_key_component_count; k++)
                            {
                                multiply_add_uint64(x0, b0[k][l], acc[k] + 2 * l);
                            }
                        }
                        j++;
                    }

                    // Reduce the accumulators if more digits follow
                    if (j < digit_count)
                    {
                        for (size_t k = 0; k < kswitch_key_component_count; k++)
                        {
                            for (size_t l = 0; l < block_size; l++)
                            {
                                unsigned long long *a = acc[k] + 2 * l;
                                a[0] = barrett_reduce_128_precomputed(
                                    a[0], a[1], mod_value, two_pow_64_mod_value, const_ratio_0, const_ratio_1);
                                a[1] = 0;
                            }
                        }
                    }
                }

                for (size_t k = 0; k < kswitch_key_component_count; k++)
                {
                    uint64_t *o = out[k] + l0;
                    const unsigned long long *a = acc[k];
                    for (size_t l = 0; l < block_size; l++)
                    {
                        o[l] = barrett_reduce_128_precomputed(
                            a[2 * l], a[2 * l + 1], mod_value, two_pow_64_mod_value, const_ratio_0, const_ratio_1);
                    }
                }
            }
        }

        // Writes out[l] = x(l) + addend[l] mod modulus, or out[l] = x(l) if addend is null, for l < coeff_count; x(l)
        // must be fully reduced and addend[l] less than modulus. out may be identical to addend.
        template <typename F>
        SEAL_FORCE_INLINE void kswitch_write_rns_component(
            size_t coeff_count, const uint64_t *addend, const Modulus &modulus, uint64_t *out, F x)
        {
            if (addend)
            {
                const uint64_t p = modulus.value();
                for (size_t l = 0; l < coeff_count; l++)
                {
                    out[l] = sub_if_ge_uint64(x(l) + addend[l], p);
                }
            }
            else
            {
                for (size_t l = 0; l < coeff_count; l++)
                {
                    out[l] = x(l);
                }
            }
        }

        // The functions kswitch_mod_down_bfv, kswitch_mod_down_ckks, and kswitch_mod_down_bgv compute one RNS
        // component modulo qi of the key-switched result divided by the special prime qk. Their input is the RNS
        // component prod modulo qi (NTT form, fully reduced) and the special-prime part t_last (coefficient form, less
        // than qk). They write the result plus addend (if not null) to out, which may be identical to prod or addend.

        // BFV: out = addend + qk^(-1) * (prod - (t_last mod qi + fix)) mod qi in coefficient form; prod is overwritten
        // by its inverse NTT. t_last is reduced modulo qi only if reduce_t_last.
        void kswitch_mod_down_bfv(
            size_t coeff_count, uint64_t *prod, const uint64_t *t_last, uint64_t fix, bool reduce_t_last,
            const Modulus &qi_mod, const MultiplyUIntModOperand &inv_qk, const NTTTables &ntt_tables,
            const uint64_t *addend, uint64_t *out)
        {
            // prod to coefficient form, in [0, 2qi)
            inverse_ntt_negacyclic_harvey_lazy(CoeffIter(prod), ntt_tables);

            // t_last mod qi + fix is in [1, 2qi], so the argument of the Shoup multiplication is in (0, 4qi)
            const uint64_t qi_lazy = qi_mod.value() << 1;
            if (reduce_t_last)
            {
                kswitch_write_rns_component(coeff_count, addend, qi_mod, out, [&](size_t l) {
                    uint64_t t = barrett_reduce_64(t_last[l], qi_mod) + fix;
                    return multiply_uint_mod(prod[l] + qi_lazy - t, inv_qk, qi_mod);
                });
            }
            else
            {
                kswitch_write_rns_component(coeff_count, addend, qi_mod, out, [&](size_t l) {
                    return multiply_uint_mod(prod[l] + qi_lazy - (t_last[l] + fix), inv_qk, qi_mod);
                });
            }
        }

        // CKKS: out = addend + qk^(-1) * (prod - NTT(t_last mod qi + fix)) mod qi in NTT form. t_last is reduced modulo
        // qi only if reduce_t_last. t_ntt is scratch space for one RNS component.
        void kswitch_mod_down_ckks(
            size_t coeff_count, const uint64_t *prod, const uint64_t *t_last, uint64_t fix, bool reduce_t_last,
            const Modulus &qi_mod, const MultiplyUIntModOperand &inv_qk, const NTTTables &ntt_tables, uint64_t *t_ntt,
            const uint64_t *addend, uint64_t *out)
        {
            if (reduce_t_last)
            {
                for (size_t l = 0; l < coeff_count; l++)
                {
                    t_ntt[l] = barrett_reduce_64(t_last[l], qi_mod) + fix;
                }
            }
            else
            {
                for (size_t l = 0; l < coeff_count; l++)
                {
                    t_ntt[l] = t_last[l] + fix;
                }
            }

            // This ntt_negacyclic_harvey_lazy results in [0, 4qi)
            ntt_negacyclic_harvey_lazy(CoeffIter(t_ntt), ntt_tables);

            // The argument of the Shoup multiplication is in (0, 5qi), and 5qi < 2^64 since qi has at most 61 bits
            const uint64_t qi_lazy = qi_mod.value() << 2;
            kswitch_write_rns_component(coeff_count, addend, qi_mod, out, [&](size_t l) {
                return multiply_uint_mod(prod[l] + qi_lazy - t_ntt[l], inv_qk, qi_mod);
            });
        }

        // BGV: out = addend + qk^(-1) * (prod - NTT(delta)) mod qi in NTT form, where delta = t_last + corr * qk.
        // t_last is reduced modulo qi only if reduce_t_last. t_delta is scratch space for one RNS component.
        void kswitch_mod_down_bgv(
            size_t coeff_count, const uint64_t *prod, const uint64_t *t_last, const uint64_t *corr,
            const MultiplyUIntModOperand &qk_mod_qi, bool reduce_t_last, const Modulus &qi_mod,
            const MultiplyUIntModOperand &inv_qk, const NTTTables &ntt_tables, uint64_t *t_delta,
            const uint64_t *addend, uint64_t *out)
        {
            // delta is computed lazily in [0, 4qi), as ntt_negacyclic_harvey_lazy requires: the Shoup multiplication
            // accepts any 64-bit input and gives [0, 2qi), and t_last (less than qk) is reduced if qk > 2qi
            if (reduce_t_last)
            {
                for (size_t l = 0; l < coeff_count; l++)
                {
                    t_delta[l] =
                        multiply_uint_mod_lazy(corr[l], qk_mod_qi, qi_mod) + barrett_reduce_64(t_last[l], qi_mod);
                }
            }
            else
            {
                for (size_t l = 0; l < coeff_count; l++)
                {
                    t_delta[l] = multiply_uint_mod_lazy(corr[l], qk_mod_qi, qi_mod) + t_last[l];
                }
            }
            ntt_negacyclic_harvey_lazy(CoeffIter(t_delta), ntt_tables);

            // delta is in [0, 4qi)
            const uint64_t qi_lazy = qi_mod.value() << 2;
            kswitch_write_rns_component(coeff_count, addend, qi_mod, out, [&](size_t l) {
                return multiply_uint_mod(prod[l] + qi_lazy - t_delta[l], inv_qk, qi_mod);
            });
        }

        // Divides the key-switched result by the special prime qk = key_modulus.back(), with rounding (BFV and CKKS) or
        // preserving the plaintext (BGV), and writes key component k of the quotient plus addends[k] (if not null) to
        // outputs[k], in the form of the ciphertexts of the scheme. Key component k is given in NTT form, fully
        // reduced: its RNS components for the primes of parms_id at prods[k] and for qk at t_lasts[k]; both are
        // overwritten. outputs[k] may be identical to prods[k] or addends[k], and outputs[1] to addends[0].
        void kswitch_mod_down(
            const SEALContext &context, parms_id_type parms_id, uint64_t *const *prods, uint64_t *const *t_lasts,
            const uint64_t *const *addends, uint64_t *const *outputs, MemoryPoolHandle pool)
        {
            auto &parms = context.get_context_data(parms_id)->parms();
            auto &key_context_data = *context.key_context_data();
            auto scheme = parms.scheme();
            size_t coeff_count = parms.poly_modulus_degree();
            size_t decomp_modulus_size = parms.coeff_modulus().size();
            auto &key_modulus = key_context_data.parms().coeff_modulus();
            auto key_ntt_tables = key_context_data.small_ntt_tables();
            auto rns_tool = key_context_data.rns_tool();
            auto modswitch_factors = rns_tool->inv_q_last_mod_q();
            uint64_t qk = key_modulus.back().value();
            uint64_t qk_half = qk >> 1;

            // Scratch space: one RNS component for CKKS; two for BGV
            Pointer<uint64_t> t_scratch;
            if (scheme == scheme_type::ckks)
            {
                t_scratch = allocate_uint(coeff_count, pool);
            }
            else if (scheme == scheme_type::bgv)
            {
                t_scratch = allocate_poly(coeff_count, 2, pool);
            }

            // Per-modulus constants. BFV and CKKS: fix = -qk_half mod qi, in [1, qi], undoes modulo qi the qk_half
            // added to t_last below. BGV: qk mod qi as a multiplication operand.
            auto fixes(allocate<uint64_t>(decomp_modulus_size, pool));
            auto qk_mod_q(allocate<MultiplyUIntModOperand>(decomp_modulus_size, pool));
            for (size_t i = 0; i < decomp_modulus_size; i++)
            {
                const Modulus &qi_mod = key_modulus[i];
                if (scheme == scheme_type::bgv)
                {
                    qk_mod_q[i].set(barrett_reduce_64(qk, qi_mod), qi_mod);
                }
                else
                {
                    fixes[i] = qi_mod.value() - barrett_reduce_64(qk_half, qi_mod);
                }
            }

            // BGV: qk^(-1) mod t
            uint64_t qk_inv_qp = 1;
            MultiplyUIntModOperand qk_inv_qp_op;
            if (scheme == scheme_type::bgv)
            {
                qk_inv_qp = rns_tool->inv_q_last_mod_t();
                qk_inv_qp_op.set(barrett_reduce_64(qk_inv_qp, parms.plain_modulus()), parms.plain_modulus());
            }

            for (size_t k = 0; k < kswitch_key_component_count; k++)
            {
                // Fully reduced inverse NTT of the special-prime part
                uint64_t *t_last = t_lasts[k];
                inverse_ntt_negacyclic_harvey(CoeffIter(t_last), key_ntt_tables[key_modulus.size() - 1]);

                if (scheme == scheme_type::bgv)
                {
                    // corr = -(t_last mod t) * qk^(-1) mod t, so that delta = t_last + corr * qk is divisible by t
                    const Modulus &plain_modulus = parms.plain_modulus();
                    uint64_t *corr = t_scratch.get() + coeff_count;
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        uint64_t v = negate_uint_mod(barrett_reduce_64(t_last[l], plain_modulus), plain_modulus);
                        corr[l] = (qk_inv_qp != 1) ? multiply_uint_mod(v, qk_inv_qp_op, plain_modulus) : v;
                    }
                }
                else
                {
                    // Add (qk - 1) / 2 to change from flooring to rounding; the result is reduced modulo qk
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        t_last[l] = sub_if_ge_uint64(t_last[l] + qk_half, qk);
                    }
                }

                for (size_t i = 0; i < decomp_modulus_size; i++)
                {
                    const Modulus &qi_mod = key_modulus[i];
                    uint64_t qi = qi_mod.value();
                    uint64_t *prod = prods[k] + i * coeff_count;
                    const uint64_t *addend = addends[k] ? addends[k] + i * coeff_count : nullptr;
                    uint64_t *out = outputs[k] + i * coeff_count;
                    switch (scheme)
                    {
                    case scheme_type::bfv:
                        kswitch_mod_down_bfv(
                            coeff_count, prod, t_last, fixes[i], qk > qi, qi_mod, modswitch_factors[i],
                            key_ntt_tables[i], addend, out);
                        break;

                    case scheme_type::ckks:
                        kswitch_mod_down_ckks(
                            coeff_count, prod, t_last, fixes[i], qk > qi, qi_mod, modswitch_factors[i],
                            key_ntt_tables[i], t_scratch.get(), addend, out);
                        break;

                    default: // scheme_type::bgv
                        kswitch_mod_down_bgv(
                            coeff_count, prod, t_last, t_scratch.get() + coeff_count, qk_mod_q[i], qk > 2 * qi, qi_mod,
                            modswitch_factors[i], key_ntt_tables[i], t_scratch.get(), addend, out);
                        break;
                    }
                }
            }
        }

        // Writes to t_ntt the digit t_src (coefficient form, values less than src_mod) in lazy NTT form modulo key_mod
        // (values in [0, 4 * key_mod)). The out-of-place lazy NTT accepts inputs in [0, 4 * key_mod), so the digit is
        // reduced modulo key_mod (on the fly) only if src_mod > 4 * key_mod; this does not overflow since key_mod has
        // at most 61 bits.
        inline void kswitch_prepare_digit(
            const uint64_t *t_src, const Modulus &src_mod, const Modulus &key_mod, const NTTTables &ntt_tables,
            uint64_t *t_ntt)
        {
            bool reduce_input = src_mod.value() > (key_mod.value() << 2);
            ntt_negacyclic_harvey_lazy(ConstCoeffIter(t_src), ntt_tables, reduce_input, CoeffIter(t_ntt));
        }

        // Writes the digits for the output RNS modulus with index i (key_index into key_modulus) to t_digits and points
        // digit_ptrs to them: digit j is RNS component j of the target t_target (coefficient form) in lazy NTT form
        // modulo key_modulus[key_index]. If ntt_target is not null (CKKS and BGV), the target is also available in NTT
        // form there, and digit i is read from it directly.
        void kswitch_prepare_digits(
            size_t i, size_t key_index, size_t coeff_count, size_t decomp_modulus_size,
            const vector<Modulus> &key_modulus, const NTTTables &ntt_tables, const uint64_t *t_target,
            const uint64_t *ntt_target, uint64_t *t_digits, const uint64_t **digit_ptrs)
        {
            for (size_t j = 0; j < decomp_modulus_size; j++)
            {
                if (ntt_target && j == i)
                {
                    digit_ptrs[j] = ntt_target + j * coeff_count;
                    continue;
                }

                uint64_t *t_ntt = t_digits + j * coeff_count;
                kswitch_prepare_digit(
                    t_target + j * coeff_count, key_modulus[j], key_modulus[key_index], ntt_tables, t_ntt);
                digit_ptrs[j] = t_ntt;
            }
        }

        // Hoisting for the output RNS modulus with index i (key_index into key_modulus, q = key_modulus[key_index]).
        // A Galois automorphism permutes the slots of NTT-form values, so the digits of an automorphism of the target
        // could be obtained by permuting the digits D_j computed by kswitch_prepare_digits. Key switching after
        // apply_galois, however, uses the digits [galois(c)]_{q_j}, lifted from [0, q_j), whereas applying galois to
        // the lifted digit [c]_{q_j} gives -x in place of q_j - x wherever the automorphism negates a coefficient x.
        // For x != 0 the difference is q_j exactly at the negated positions, i.e., q_j * (1 - galois(1)) / 2 with 1 the
        // all-ones polynomial. This function therefore writes D_j - F_j to t_digits and F_j to t_corrections, where
        // F_j = (q_j * 2^(-1) mod q) * NTT(1), so that permute(D_j - F_j) + F_j as read by kswitch_dot_product is the
        // exact digit of the automorphism. Digit i needs no correction (q_i = 0 modulo q). A digit with a zero
        // coefficient (0 maps to 0, not q_j) must instead be recomputed for each automorphism, so for such a digit
        // j != i the caller sets digit_ptrs[j]. Every correction pointer is set, to t_zero if there is no correction.
        void kswitch_hoist_digits(
            size_t i, size_t key_index, size_t coeff_count, size_t decomp_modulus_size,
            const vector<Modulus> &key_modulus, const NTTTables &ntt_tables, const uint64_t *t_target,
            const uint64_t *ntt_target, const vector<uint8_t> &digit_has_zero, const uint64_t *t_zero,
            uint64_t *t_ones_ntt, uint64_t *t_digits, uint64_t *t_corrections, const uint64_t **digit_ptrs,
            const uint64_t **correction_ptrs)
        {
            const Modulus &key_mod = key_modulus[key_index];
            const uint64_t q = key_mod.value();
            const uint64_t two_q = q << 1;

            // NTT of the all-ones polynomial modulo q
            fill_n(t_ones_ntt, coeff_count, uint64_t(1));
            ntt_negacyclic_harvey(CoeffIter(t_ones_ntt), ntt_tables);
            const uint64_t inv2 = (q + 1) >> 1; // 2^(-1) mod q

            for (size_t j = 0; j < decomp_modulus_size; j++)
            {
                correction_ptrs[j] = t_zero;
                if (j == i)
                {
                    // The digit stays in [0, 4q) and needs no correction
                    if (ntt_target)
                    {
                        digit_ptrs[j] = ntt_target + j * coeff_count;
                    }
                    else
                    {
                        kswitch_prepare_digit(
                            t_target + j * coeff_count, key_modulus[j], key_mod, ntt_tables,
                            t_digits + j * coeff_count);
                        digit_ptrs[j] = t_digits + j * coeff_count;
                    }
                    continue;
                }
                if (digit_has_zero[j])
                {
                    continue;
                }

                uint64_t *d = t_digits + j * coeff_count;
                uint64_t *f = t_corrections + j * coeff_count;
                kswitch_prepare_digit(t_target + j * coeff_count, key_modulus[j], key_mod, ntt_tables, d);
                MultiplyUIntModOperand factor;
                factor.set(
                    multiply_uint_mod(barrett_reduce_64(key_modulus[j].value(), key_mod), inv2, key_mod), key_mod);
                for (size_t l = 0; l < coeff_count; l++)
                {
                    // Reduce the lazy NTT output to [0, q), as sub_uint_mod requires. Then d[l] and f[l] are both in
                    // [0, q), so the value d[perm[l]] + f[l] read by kswitch_dot_product is below 2q, within its
                    // [0, 4q) input bound.
                    uint64_t fl = multiply_uint_mod(t_ones_ntt[l], factor, key_mod);
                    uint64_t dl = sub_if_ge_uint64(sub_if_ge_uint64(d[l], two_q), q);
                    d[l] = sub_uint_mod(dl, fl, key_mod);
                    f[l] = fl;
                }
                digit_ptrs[j] = d;
                correction_ptrs[j] = f;
            }
        }

        // Points key_ptrs[2 * j + k] to RNS component key_index of component k of key j, for j < decomp_modulus_size
        void kswitch_set_key_ptrs(
            size_t key_index, size_t coeff_count, size_t decomp_modulus_size, const vector<PublicKey> &key_vector,
            const uint64_t **key_ptrs)
        {
            for (size_t j = 0; j < decomp_modulus_size; j++)
            {
                for (size_t k = 0; k < kswitch_key_component_count; k++)
                {
                    key_ptrs[j * kswitch_key_component_count + k] =
                        key_vector[j].data().data(k) + key_index * coeff_count;
                }
            }
        }

        // Returns the RNS components of target, which is in the form of the ciphertexts of scheme, in coefficient form:
        // target itself for BFV, or its inverse NTT, written to t_copy, for CKKS and BGV
        const uint64_t *kswitch_target_to_coeff_form(
            ConstRNSIter target, size_t decomp_modulus_size, scheme_type scheme, ConstNTTTablesIter ntt_tables,
            Pointer<uint64_t> &t_copy, MemoryPoolHandle pool)
        {
            if (scheme == scheme_type::bfv)
            {
                return target;
            }
            size_t coeff_count = target.poly_modulus_degree();
            t_copy = allocate_poly(coeff_count, decomp_modulus_size, pool);

            // Out-of-place inverse NTT, fully reduced
            inverse_ntt_negacyclic_harvey(target, decomp_modulus_size, ntt_tables, RNSIter(t_copy.get(), coeff_count));
            return t_copy.get();
        }
    } // namespace

    void Evaluator::switch_key(
        parms_id_type parms_id, ConstRNSIter target_iter, const vector<PublicKey> &key_vector,
        const uint64_t *const *addends, uint64_t *const *outputs, MemoryPoolHandle pool) const
    {
        // Assuming at this point the inputs are validated.
        auto &parms = context_.get_context_data(parms_id)->parms();
        auto scheme = parms.scheme();
        auto &key_context_data = *context_.key_context_data();
        auto &key_modulus = key_context_data.parms().coeff_modulus();
        size_t key_modulus_size = key_modulus.size();
        auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
        size_t coeff_count = parms.poly_modulus_degree();
        size_t decomp_modulus_size = parms.coeff_modulus().size();
        size_t rns_modulus_size = decomp_modulus_size + 1;

        // Digits in coefficient form. In BFV, target_iter is used directly; it is read only before outputs are written.
        Pointer<uint64_t> t_target_copy;
        const uint64_t *t_target =
            kswitch_target_to_coeff_form(target_iter, decomp_modulus_size, scheme, key_ntt_tables, t_target_copy, pool);
        const uint64_t *ntt_target =
            (scheme == scheme_type::bfv) ? nullptr : static_cast<const uint64_t *>(target_iter);

        // Accumulated products (NTT form, fully reduced); layout [key component][RNS modulus][coeff]. Every
        // coefficient is written by the dot products below, so no zero-initialization is needed.
        auto t_poly_prod(allocate_poly_array(kswitch_key_component_count, coeff_count, rns_modulus_size, pool));
        uint64_t *prods[kswitch_key_component_count];
        uint64_t *t_lasts[kswitch_key_component_count];
        for (size_t k = 0; k < kswitch_key_component_count; k++)
        {
            prods[k] = t_poly_prod.get() + k * rns_modulus_size * coeff_count;
            t_lasts[k] = prods[k] + decomp_modulus_size * coeff_count;
        }

        // NTT-form digits for the current output modulus, and pointer tables for the dot products
        auto t_digits(allocate_poly(coeff_count, decomp_modulus_size, pool));
        auto digit_ptrs(allocate<const uint64_t *>(decomp_modulus_size, pool));
        auto key_ptrs(allocate<const uint64_t *>(mul_safe(decomp_modulus_size, kswitch_key_component_count), pool));
        auto acc_scratch(allocate<unsigned long long>(kswitch_acc_scratch_size, pool));

        for (size_t i = 0; i < rns_modulus_size; i++)
        {
            size_t key_index = (i == decomp_modulus_size ? key_modulus_size - 1 : i);

            // Prepare all digits modulo key_modulus[key_index] in NTT form
            kswitch_prepare_digits(
                i, key_index, coeff_count, decomp_modulus_size, key_modulus, key_ntt_tables[key_index], t_target,
                ntt_target, t_digits.get(), digit_ptrs.get());
            kswitch_set_key_ptrs(key_index, coeff_count, decomp_modulus_size, key_vector, key_ptrs.get());

            // Multiply with keys and accumulate; outputs are fully reduced modulo key_modulus[key_index]
            uint64_t *out_ptrs[kswitch_key_component_count]{ prods[0] + i * coeff_count, prods[1] + i * coeff_count };
            kswitch_dot_product<false>(
                coeff_count, decomp_modulus_size, digit_ptrs.get(), nullptr, nullptr, key_ptrs.get(),
                key_modulus[key_index], out_ptrs, acc_scratch.get());
        }

        // Perform modulus switching with scaling
        kswitch_mod_down(context_, parms_id, prods, t_lasts, addends, outputs, std::move(pool));
    }

    void Evaluator::apply_galois_hoisted(
        const Ciphertext &encrypted, const vector<uint32_t> &galois_elts, const GaloisKeys &galois_keys,
        const vector<Ciphertext *> &destinations, MemoryPoolHandle pool) const
    {
        // Assuming at this point the inputs are validated and the destinations are distinct from encrypted.
        auto parms_id = encrypted.parms_id();
        auto &parms = context_.get_context_data(parms_id)->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto scheme = parms.scheme();
        auto &key_context_data = *context_.key_context_data();
        auto &key_modulus = key_context_data.parms().coeff_modulus();
        size_t key_modulus_size = key_modulus.size();
        auto key_ntt_tables = iter(key_context_data.small_ntt_tables());
        size_t coeff_count = parms.poly_modulus_degree();
        size_t decomp_modulus_size = coeff_modulus.size();
        size_t rns_modulus_size = decomp_modulus_size + 1;
        size_t elt_count = galois_elts.size();
        // Use key_context_data where permutation tables exist since previous runs.
        auto galois_tool = key_context_data.galois_tool();

        // The key-switched RNS components for the primes of encrypted are written directly to the destinations
        for (auto destination : destinations)
        {
            destination->resize(context_, parms_id, 2);
            destination->is_ntt_form() = encrypted.is_ntt_form();
            destination->scale() = encrypted.scale();
            destination->correction_factor() = encrypted.correction_factor();
        }

        // Digits (RNS components) of encrypted.data(1) in coefficient form
        ConstRNSIter target_iter(encrypted.data(1), coeff_count);
        Pointer<uint64_t> t_target_copy;
        const uint64_t *t_target =
            kswitch_target_to_coeff_form(target_iter, decomp_modulus_size, scheme, key_ntt_tables, t_target_copy, pool);
        const uint64_t *ntt_target = (scheme == scheme_type::bfv) ? nullptr : encrypted.data(1);

        // Digits with a zero coefficient are recomputed for each automorphism (see kswitch_hoist_digits)
        vector<uint8_t> digit_has_zero(decomp_modulus_size);
        bool any_digit_has_zero = false;
        for (size_t j = 0; j < decomp_modulus_size; j++)
        {
            const uint64_t *digit = t_target + j * coeff_count;
            digit_has_zero[j] = any_of(digit, digit + coeff_count, [](uint64_t x) { return !x; });
            any_digit_has_zero = any_digit_has_zero || digit_has_zero[j];
        }

        // Scratch space for the hoisted digits and their corrections for one output modulus, the key-switched RNS
        // components for the special prime (layout [automorphism][key component][coeff]), and pointer tables
        auto t_digits(allocate_poly(coeff_count, decomp_modulus_size, pool));
        auto t_corrections(allocate_poly(coeff_count, decomp_modulus_size, pool));
        auto t_ones_ntt(allocate_uint(coeff_count, pool));
        auto t_zero(allocate_zero_uint(coeff_count, pool));
        auto t_lasts(allocate_poly_array(elt_count, coeff_count, kswitch_key_component_count, pool));
        auto digit_ptrs(allocate<const uint64_t *>(decomp_modulus_size, pool));
        auto correction_ptrs(allocate<const uint64_t *>(decomp_modulus_size, pool));
        auto key_ptrs(allocate<const uint64_t *>(mul_safe(decomp_modulus_size, kswitch_key_component_count), pool));
        auto acc_scratch(allocate<unsigned long long>(kswitch_acc_scratch_size, pool));

        // Scratch space for recomputing digits with a zero coefficient: one in coefficient form and in NTT form, and
        // all of them stored for the permuted read
        Pointer<uint64_t> t_exact;
        Pointer<uint64_t> t_exact_scattered;
        if (any_digit_has_zero)
        {
            t_exact = allocate_poly(coeff_count, 2, pool);
            t_exact_scattered = allocate_poly(coeff_count, decomp_modulus_size, pool);
        }

        // The key switching keys and permutation tables of the automorphisms
        vector<const vector<PublicKey> *> key_vectors(elt_count);
        vector<const uint32_t *> perms(elt_count);
        for (size_t e = 0; e < elt_count; e++)
        {
            key_vectors[e] = &galois_keys.data(GaloisKeys::get_index(galois_elts[e]));
            perms[e] = galois_tool->get_permutation_table_ntt(galois_elts[e]);
        }

        for (size_t i = 0; i < rns_modulus_size; i++)
        {
            size_t key_index = (i == decomp_modulus_size ? key_modulus_size - 1 : i);
            const Modulus &key_mod = key_modulus[key_index];
            const NTTTables &ntt_tables = key_ntt_tables[key_index];

            // The digits modulo key_mod are computed once and used for all automorphisms
            kswitch_hoist_digits(
                i, key_index, coeff_count, decomp_modulus_size, key_modulus, ntt_tables, t_target, ntt_target,
                digit_has_zero, t_zero.get(), t_ones_ntt.get(), t_digits.get(), t_corrections.get(), digit_ptrs.get(),
                correction_ptrs.get());

            for (size_t e = 0; e < elt_count; e++)
            {
                const uint32_t *perm = perms[e];

                // Digits with a zero coefficient, except digit i, which is exact: the exact NTT-form digits
                // [galois(c1)]_{q_j}, as in switch_key, stored such that the permuted read in the dot product
                // recovers them
                for (size_t j = 0; j < decomp_modulus_size; j++)
                {
                    if (!digit_has_zero[j] || j == i)
                    {
                        continue;
                    }
                    uint64_t *t_exact_coeff = t_exact.get();
                    uint64_t *t_exact_ntt = t_exact.get() + coeff_count;
                    uint64_t *t_scattered = t_exact_scattered.get() + j * coeff_count;
                    galois_tool->apply_galois(
                        ConstCoeffIter(t_target + j * coeff_count), galois_elts[e], key_modulus[j],
                        CoeffIter(t_exact_coeff));
                    kswitch_prepare_digit(t_exact_coeff, key_modulus[j], key_mod, ntt_tables, t_exact_ntt);
                    for (size_t l = 0; l < coeff_count; l++)
                    {
                        t_scattered[perm[l]] = t_exact_ntt[l];
                    }
                    digit_ptrs[j] = t_scattered;
                }

                // The automorphism is applied to the hoisted digits on the fly by a permuted read plus correction
                kswitch_set_key_ptrs(key_index, coeff_count, decomp_modulus_size, *key_vectors[e], key_ptrs.get());
                uint64_t *out_ptrs[kswitch_key_component_count];
                for (size_t k = 0; k < kswitch_key_component_count; k++)
                {
                    out_ptrs[k] = (i < decomp_modulus_size)
                                      ? destinations[e]->data(k) + i * coeff_count
                                      : t_lasts.get() + (e * kswitch_key_component_count + k) * coeff_count;
                }
                kswitch_dot_product<true>(
                    coeff_count, decomp_modulus_size, digit_ptrs.get(), perm, correction_ptrs.get(), key_ptrs.get(),
                    key_mod, out_ptrs, acc_scratch.get());
            }
        }

        // Divide by the special prime and add galois(c0), computed in t_digits, which is no longer needed
        for (size_t e = 0; e < elt_count; e++)
        {
            Ciphertext &destination = *destinations[e];
            RNSIter galois_c0(t_digits.get(), coeff_count);
            if (scheme == scheme_type::bfv)
            {
                galois_tool->apply_galois(
                    ConstRNSIter(encrypted.data(0), coeff_count), decomp_modulus_size, galois_elts[e], coeff_modulus,
                    galois_c0);
            }
            else
            {
                galois_tool->apply_galois_ntt(
                    ConstRNSIter(encrypted.data(0), coeff_count), decomp_modulus_size, galois_elts[e], galois_c0);
            }

            uint64_t *prods[kswitch_key_component_count]{ destination.data(0), destination.data(1) };
            uint64_t *t_last_ptrs[kswitch_key_component_count]{
                t_lasts.get() + e * kswitch_key_component_count * coeff_count,
                t_lasts.get() + (e * kswitch_key_component_count + 1) * coeff_count
            };
            const uint64_t *addends[kswitch_key_component_count]{ galois_c0, nullptr };
            kswitch_mod_down(context_, parms_id, prods, t_last_ptrs, addends, prods, pool);
#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
            // Transparent ciphertext output is not allowed.
            if (destination.is_transparent())
            {
                throw logic_error("result ciphertext is transparent");
            }
#endif
        }
    }

    void Evaluator::rotate_many_internal(
        const Ciphertext &encrypted, const vector<int> &steps, const GaloisKeys &galois_keys,
        vector<Ciphertext> &destinations, MemoryPoolHandle pool) const
    {
        auto context_data_ptr = context_.get_context_data(encrypted.parms_id());
        if (!context_data_ptr)
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }
        if (!context_data_ptr->qualifiers().using_batching)
        {
            throw logic_error("encryption parameters do not support batching");
        }
        if (galois_keys.parms_id() != context_.key_parms_id())
        {
            throw invalid_argument("galois_keys is not valid for encryption parameters");
        }
        if (!pool)
        {
            throw invalid_argument("pool is uninitialized");
        }

        // Verify all steps and the keys they need before any work is done, as rotate_internal would for each step.
        // Steps with their own Galois key are hoisted together; other nonzero steps are composed of several rotations.
        size_t coeff_count = context_data_ptr->parms().poly_modulus_degree();
        auto galois_tool = context_data_ptr->galois_tool();
        vector<uint32_t> hoisted_elts;
        vector<size_t> hoisted_indices;
        vector<size_t> composed_indices;
        for (size_t i = 0; i < steps.size(); i++)
        {
            if (steps[i] == 0)
            {
                continue;
            }
            uint32_t galois_elt = galois_tool->get_elt_from_step(steps[i]);
            if (galois_keys.has_key(galois_elt))
            {
                validate_galois(context_, encrypted, galois_elt, galois_keys);
                hoisted_elts.push_back(galois_elt);
                hoisted_indices.push_back(i);
                continue;
            }

            vector<int> naf_steps = naf(steps[i]);
            if (naf_steps.size() == 1)
            {
                throw invalid_argument("Galois key not present");
            }
            for (int naf_step : naf_steps)
            {
                // A NAF term of size coeff_count / 2 corresponds to no rotation and is skipped
                if (safe_cast<size_t>(abs(naf_step)) == (coeff_count >> 1))
                {
                    continue;
                }
                uint32_t naf_elt = galois_tool->get_elt_from_step(naf_step);
                if (!galois_keys.has_key(naf_elt))
                {
                    throw invalid_argument("Galois key not present");
                }
                validate_galois(context_, encrypted, naf_elt, galois_keys);
            }
            composed_indices.push_back(i);
        }

        // encrypted may be an element of destinations; if so, it is copied before destinations is modified
        const Ciphertext *source = &encrypted;
        Ciphertext encrypted_copy(pool);
        for (const auto &destination : destinations)
        {
            if (&destination == &encrypted)
            {
                encrypted_copy = encrypted;
                source = &encrypted_copy;
                break;
            }
        }

        // Existing elements of destinations keep their memory pools; new elements use pool
        while (destinations.size() > steps.size())
        {
            destinations.pop_back();
        }
        destinations.reserve(steps.size());
        while (destinations.size() < steps.size())
        {
            destinations.emplace_back(pool);
        }

        // Steps that are zero or composed of several rotations are done as in rotate_internal
        for (size_t i = 0; i < steps.size(); i++)
        {
            if (steps[i] == 0)
            {
                destinations[i] = *source;
            }
        }
        for (auto i : composed_indices)
        {
            destinations[i] = *source;
            rotate_internal(destinations[i], steps[i], galois_keys, pool);
        }

        if (hoisted_elts.size() == 1)
        {
            // Hoisting does not pay off for a single rotation
            Ciphertext &destination = destinations[hoisted_indices[0]];
            destination = *source;
            apply_galois_inplace(destination, hoisted_elts[0], galois_keys, std::move(pool));
        }
        else if (hoisted_elts.size() > 1)
        {
            vector<Ciphertext *> hoisted_destinations(hoisted_indices.size());
            for (size_t i = 0; i < hoisted_indices.size(); i++)
            {
                hoisted_destinations[i] = &destinations[hoisted_indices[i]];
            }
            apply_galois_hoisted(*source, hoisted_elts, galois_keys, hoisted_destinations, std::move(pool));
        }
    }
} // namespace seal

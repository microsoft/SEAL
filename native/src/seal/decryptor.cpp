// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <algorithm>
#include <stdexcept>
#include "seal/decryptor.h"
#include "seal/valcheck.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/polyarithmod.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/scalingvariant.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    Decryptor::Decryptor(shared_ptr<SEALContext> context,
        const SecretKey &secret_key) : context_(move(context))
    {
        // Verify parameters
        if (!context_)
        {
            throw invalid_argument("invalid context");
        }
        if (!context_->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }
        if (!is_valid_for(secret_key, context_))
        {
            throw invalid_argument("secret key is not valid for encryption parameters");
        }

        auto &parms = context_->key_context_data()->parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Set the secret_key_array to have size 1 (first power of secret)
        // and copy over data
        secret_key_array_ = allocate_poly(coeff_count, coeff_mod_count, pool_);
        set_poly_poly(secret_key.data().data(), coeff_count, coeff_mod_count,
            secret_key_array_.get());
        secret_key_array_size_ = 1;
    }

    void Decryptor::decrypt(const Ciphertext &encrypted, Plaintext &destination)
    {
        // Verify that encrypted is valid.
        if (!is_valid_for(encrypted, context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        auto &context_data = *context_->first_context_data();
        auto &parms = context_data.parms();

        switch (parms.scheme())
        {
        case scheme_type::BFV:
            bfv_decrypt(encrypted, destination, pool_);
            return;

        case scheme_type::CKKS:
            ckks_decrypt(encrypted, destination, pool_);
            return;

        default:
            throw invalid_argument("unsupported scheme");
        }
    }

    void Decryptor::bfv_decrypt(const Ciphertext &encrypted,
        Plaintext &destination, MemoryPoolHandle pool)
    {
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_->get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // Add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
        // Therefore, we can (integer) divide by Delta and the answer will round down to m.

        // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
        auto tmp_dest_modq(allocate_zero_poly(coeff_count, coeff_mod_count, pool));

        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dot_product_ct_sk_array(encrypted, tmp_dest_modq.get(), pool_);

        // Allocate a full size destination to write to
        destination.resize(coeff_count);

        // Divide scaling variant using Bajard FullRNS techniques.
        divide_phase_by_scaling_variant(tmp_dest_modq.get(), context_data,
            destination.data(), pool);

        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = get_significant_uint64_count_uint(
            destination.data(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
        destination.parms_id() = parms_id_zero;
    }

    void Decryptor::ckks_decrypt(const Ciphertext &encrypted,
        Plaintext &destination, MemoryPoolHandle pool)
    {
        if (!encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted must be in NTT form");
        }

        // We already know that the parameters are valid
        auto &context_data = *context_->get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);

        // Decryption consists in finding
        // c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
        // as long as ||m + v|| < q_1 * q_2 * q_3.
        // This is equal to m + v where ||v|| is small enough.

        // Since we overwrite destination, we zeroize destination parameters
        // This is necessary, otherwise resize will throw an exception.
        destination.parms_id() = parms_id_zero;

        // Resize destination to appropriate size
        destination.resize(rns_poly_uint64_count);

        // Make a temp destination for all the arithmetic mod q1, q2, q3
        //auto tmp_dest_modq(allocate_zero_poly(coeff_count, decryption_coeff_mod_count, pool));
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dot_product_ct_sk_array(encrypted, destination.data(), pool);

        // Set destination parameters as in encrypted
        destination.parms_id() = encrypted.parms_id();
        destination.scale() = encrypted.scale();
    }

    void Decryptor::compute_secret_key_array(size_t max_power)
    {
#ifdef SEAL_DEBUG
        if (max_power < 1)
        {
            throw invalid_argument("max_power must be at least 1");
        }
        if (!secret_key_array_size_ || !secret_key_array_)
        {
            throw logic_error("secret_key_array_ is uninitialized");
        }
#endif
        // WARNING: This function must be called with the original context_data
        auto &context_data = *context_->key_context_data();
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t key_rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);

        ReaderLock reader_lock(secret_key_array_locker_.acquire_read());

        size_t old_size = secret_key_array_size_;
        size_t new_size = max(max_power, old_size);

        if (old_size == new_size)
        {
            return;
        }

        reader_lock.unlock();

        // Need to extend the array
        // Compute powers of secret key until max_power
        auto new_secret_key_array(allocate_poly(
            mul_safe(new_size, coeff_count), coeff_mod_count, pool_));
        set_poly_poly(secret_key_array_.get(), old_size * coeff_count,
            coeff_mod_count, new_secret_key_array.get());

        set_poly_poly(secret_key_array_.get(), mul_safe(old_size, coeff_count),
            coeff_mod_count, new_secret_key_array.get());

        uint64_t *prev_poly_ptr = new_secret_key_array.get() +
            mul_safe(old_size - 1, key_rns_poly_uint64_count);
        uint64_t *next_poly_ptr = prev_poly_ptr + key_rns_poly_uint64_count;

        // Since all of the key powers in secret_key_array_ are already NTT transformed,
        // to get the next one we simply need to compute a dyadic product of the last
        // one with the first one [which is equal to NTT(secret_key_)].
        for (size_t i = old_size; i < new_size; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                dyadic_product_coeffmod(prev_poly_ptr + (j * coeff_count),
                    new_secret_key_array.get() + (j * coeff_count),
                    coeff_count, coeff_modulus[j],
                    next_poly_ptr + (j * coeff_count));
            }
            prev_poly_ptr = next_poly_ptr;
            next_poly_ptr += key_rns_poly_uint64_count;
        }


        // Take writer lock to update array
        WriterLock writer_lock(secret_key_array_locker_.acquire_write());

        // Do we still need to update size?
        old_size = secret_key_array_size_;
        new_size = max(max_power, secret_key_array_size_);

        if (old_size == new_size)
        {
            return;
        }

        // Acquire new array
        secret_key_array_size_ = new_size;
        secret_key_array_.acquire(new_secret_key_array);
    }

    // Compute c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q.
    // Store result in destination in RNS form.
    void Decryptor::dot_product_ct_sk_array(
        const Ciphertext &encrypted,
        uint64_t *destination,
        MemoryPoolHandle pool)
    {
        auto &context_data = *context_->get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);
        size_t key_rns_poly_uint64_count = mul_safe(coeff_count,
            context_->key_context_data()->parms().coeff_modulus().size());
        size_t encrypted_size = encrypted.size();
        auto is_ntt_form = encrypted.is_ntt_form();

        auto &small_ntt_tables = context_data.small_ntt_tables();

        // Make sure we have enough secret key powers computed
        compute_secret_key_array(encrypted_size - 1);

        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination

        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        auto copy_operand1(allocate_uint(coeff_count, pool));

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Initialize pointers for multiplication
            const uint64_t *encrypted_ptr = encrypted.data(1) + (i * coeff_count);
            const uint64_t *secret_key_ptr = secret_key_array_.get() + (i * coeff_count);
            uint64_t *destination_ptr = destination + (i * coeff_count);
            set_zero_uint(coeff_count, destination_ptr);
            for (size_t j = 0; j < encrypted_size - 1; j++)
            {
                set_uint_uint(encrypted_ptr, coeff_count, copy_operand1.get());
                if (!is_ntt_form)
                {
                    ntt_negacyclic_harvey_lazy(copy_operand1.get(), small_ntt_tables[i]);
                }
                // compute c_{j+1} * s^{j+1}
                dyadic_product_coeffmod(copy_operand1.get(), secret_key_ptr, coeff_count,
                    coeff_modulus[i], copy_operand1.get());
                // add c_{j+1} * s^{j+1} to destination
                add_poly_poly_coeffmod(destination_ptr,
                    copy_operand1.get(), coeff_count, coeff_modulus[i],
                    destination_ptr);
                encrypted_ptr += rns_poly_uint64_count;
                secret_key_ptr += key_rns_poly_uint64_count;
            }
            if (!is_ntt_form)
            {
                inverse_ntt_negacyclic_harvey(destination_ptr, small_ntt_tables[i]);
            }
            // add c_0 into destination
            add_poly_poly_coeffmod(destination_ptr,
                encrypted.data() + (i * coeff_count), coeff_count, coeff_modulus[i],
                destination_ptr);
        }
    }

    void Decryptor::compose(
        const SEALContext::ContextData &context_data, uint64_t *value)
    {
#ifdef SEAL_DEBUG
        if (value == nullptr)
        {
            throw invalid_argument("input cannot be null");
        }
#endif
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);

        auto &base_converter = context_data.base_converter();
        auto coeff_products_array = base_converter->get_coeff_products_array();
        auto &inv_coeff_mod_coeff_array = base_converter->get_inv_coeff_mod_coeff_array();

        // Set temporary coefficients_ptr pointer to point to either an existing
        // allocation given as parameter, or else to a new allocation from the memory pool.
        auto coefficients(allocate_uint(rns_poly_uint64_count, pool_));
        uint64_t *coefficients_ptr = coefficients.get();

        // Re-merge the coefficients first
        for (size_t i = 0; i < coeff_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                coefficients_ptr[j + (i * coeff_mod_count)] = value[(j * coeff_count) + i];
            }
        }

        auto temp(allocate_uint(coeff_mod_count, pool_));
        set_zero_uint(rns_poly_uint64_count, value);

        for (size_t i = 0; i < coeff_count; i++)
        {
            for (size_t j = 0; j < coeff_mod_count; j++)
            {
                uint64_t tmp = multiply_uint_uint_mod(coefficients_ptr[j],
                    inv_coeff_mod_coeff_array[j], coeff_modulus[j]);
                multiply_uint_uint64(coeff_products_array + (j * coeff_mod_count),
                    coeff_mod_count, tmp, coeff_mod_count, temp.get());
                add_uint_uint_mod(temp.get(), value + (i * coeff_mod_count),
                    context_data.total_coeff_modulus(),
                    coeff_mod_count, value + (i * coeff_mod_count));
            }
            set_zero_uint(coeff_mod_count, temp.get());
            coefficients_ptr += coeff_mod_count;
        }
    }

    int Decryptor::invariant_noise_budget(const Ciphertext &encrypted)
    {
        // Verify that encrypted is valid.
        if (!is_valid_for(encrypted, context_))
        {
            throw invalid_argument("encrypted is not valid for encryption parameters");
        }

        if (context_->key_context_data()->parms().scheme() != scheme_type::BFV)
        {
            throw logic_error("unsupported scheme");
        }
        if (encrypted.is_ntt_form())
        {
            throw invalid_argument("encrypted cannot be in NTT form");
        }

        auto &context_data = *context_->get_context_data(encrypted.parms_id());
        auto &parms = context_data.parms();
        auto &coeff_modulus = parms.coeff_modulus();
        auto &plain_modulus = parms.plain_modulus();
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();

        // Storage for the infinity norm of noise poly
        auto norm(allocate_uint(coeff_mod_count, pool_));

        // Storage for noise poly
        auto noise_poly(allocate_zero_poly(coeff_count, coeff_mod_count, pool_));

        // Now need to compute c(s) - Delta*m (mod q)
        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
        // in destination_poly.
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        dot_product_ct_sk_array(encrypted, noise_poly.get(), pool_);

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Multiply by plain_modulus and reduce mod coeff_modulus to get
            // coeff_modulus()*noise.
            multiply_poly_scalar_coeffmod(noise_poly.get() + i * coeff_count,
                coeff_count, plain_modulus.value(), coeff_modulus[i],
                noise_poly.get() + i * coeff_count);
        }

        // Compose the noise
        compose(context_data, noise_poly.get());

        // Next we compute the infinity norm mod parms.coeff_modulus()
        poly_infty_norm_coeffmod(noise_poly.get(), coeff_count, coeff_mod_count,
            context_data.total_coeff_modulus(), norm.get(), pool_);

        // The -1 accounts for scaling the invariant noise by 2;
        // note that we already took plain_modulus into account in compose
        // so no need to subtract log(plain_modulus) from this
        int bit_count_diff = context_data.total_coeff_modulus_bit_count() -
            get_significant_bit_count_uint(norm.get(), coeff_mod_count) - 1;
        return max(0, bit_count_diff);
    }
}

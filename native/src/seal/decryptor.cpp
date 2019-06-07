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

using namespace std;
using namespace seal::util;

namespace seal
{
    Decryptor::Decryptor(std::shared_ptr<SEALContext> context,
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
        if (secret_key.parms_id() != context_->key_parms_id())
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
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);
        size_t key_rns_poly_uint64_count = mul_safe(coeff_count,
            context_->key_context_data()->parms().coeff_modulus().size());
        size_t encrypted_size = encrypted.size();

        auto &small_ntt_tables = context_data.small_ntt_tables();
        auto &base_converter = context_data.base_converter();
        auto &plain_gamma_product = base_converter->get_plain_gamma_product();
        auto &plain_gamma_array = base_converter->get_plain_gamma_array();
        auto &neg_inv_coeff = base_converter->get_neg_inv_coeff();
        auto inv_gamma = base_converter->get_inv_gamma();

        // The number of uint64 count for plain_modulus and gamma together
        size_t plain_gamma_uint64_count = 2;

        // Allocate a full size destination to write to
        auto wide_destination(allocate_uint(coeff_count, pool));

        // Make sure we have enough secret key powers computed
        compute_secret_key_array(encrypted_size - 1);

        /*
        Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        This is equal to Delta m + v where ||v|| < Delta/2.
        So, add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
        Therefore, we can (integer) divide by Delta and the answer will round down to m.
        */

        // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
        auto tmp_dest_modq(allocate_zero_poly(coeff_count, coeff_mod_count, pool));

        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination

        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        auto copy_operand1(allocate_uint(coeff_count, pool));
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Initialize pointers for multiplication
            const uint64_t *current_array1 = encrypted.data(1) + (i * coeff_count);
            const uint64_t *current_array2 = secret_key_array_.get() + (i * coeff_count);

            for (size_t j = 0; j < encrypted_size - 1; j++)
            {
                // Perform the dyadic product.
                set_uint_uint(current_array1, coeff_count, copy_operand1.get());

                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_operand1.get(), small_ntt_tables[i]);

                dyadic_product_coeffmod(copy_operand1.get(), current_array2, coeff_count,
                    coeff_modulus[i], copy_operand1.get());
                add_poly_poly_coeffmod(tmp_dest_modq.get() + (i * coeff_count),
                    copy_operand1.get(), coeff_count, coeff_modulus[i],
                    tmp_dest_modq.get() + (i * coeff_count));

                current_array1 += rns_poly_uint64_count;
                current_array2 += key_rns_poly_uint64_count;
            }

            // Perform inverse NTT
            inverse_ntt_negacyclic_harvey(tmp_dest_modq.get() + (i * coeff_count),
                small_ntt_tables[i]);
        }

        // add c_0 into destination
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            //add_poly_poly_coeffmod(tmp_dest_modq.get() + (i * coeff_count),
            //  encrypted.data() + (i * coeff_count), coeff_count, coeff_modulus_[i],
            //  tmp_dest_modq.get() + (i * coeff_count));

            // Lazy reduction
            for (size_t j = 0; j < coeff_count; j++)
            {
                tmp_dest_modq[j + (i * coeff_count)] += encrypted[j + (i * coeff_count)];
            }

            // Compute |gamma * plain|qi * ct(s)
            multiply_poly_scalar_coeffmod(tmp_dest_modq.get() + (i * coeff_count), coeff_count,
                plain_gamma_product[i], coeff_modulus[i], tmp_dest_modq.get() + (i * coeff_count));
        }

        // Make another temp destination to get the poly in mod {gamma U plain_modulus}
        auto tmp_dest_plain_gamma(allocate_poly(coeff_count, plain_gamma_uint64_count, pool));

        // Compute FastBConvert from q to {gamma, plain_modulus}
        base_converter->fastbconv_plain_gamma(tmp_dest_modq.get(), tmp_dest_plain_gamma.get(), pool);

        // Compute result multiply by coeff_modulus inverse in mod {gamma U plain_modulus}
        for (size_t i = 0; i < plain_gamma_uint64_count; i++)
        {
            multiply_poly_scalar_coeffmod(tmp_dest_plain_gamma.get() + (i * coeff_count),
                coeff_count, neg_inv_coeff[i], plain_gamma_array[i],
                tmp_dest_plain_gamma.get() + (i * coeff_count));
        }

        // First correct the values which are larger than floor(gamma/2)
        uint64_t gamma_div_2 = plain_gamma_array[1].value() >> 1;

        // Now compute the subtraction to remove error and perform final multiplication by
        // gamma inverse mod plain_modulus
        for (size_t i = 0; i < coeff_count; i++)
        {
            // Need correction beacuse of center mod
            if (tmp_dest_plain_gamma[i + coeff_count] > gamma_div_2)
            {
                // Compute -(gamma - a) instead of (a - gamma)
                tmp_dest_plain_gamma[i + coeff_count] = plain_gamma_array[1].value() -
                    tmp_dest_plain_gamma[i + coeff_count];
                tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                wide_destination[i] = add_uint_uint_mod(tmp_dest_plain_gamma[i],
                    tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
            }
            // No correction needed
            else
            {
                tmp_dest_plain_gamma[i + coeff_count] %= plain_gamma_array[0].value();
                wide_destination[i] = sub_uint_uint_mod(tmp_dest_plain_gamma[i],
                    tmp_dest_plain_gamma[i + coeff_count], plain_gamma_array[0]);
            }
        }

        // How many non-zero coefficients do we really have in the result?
        size_t plain_coeff_count = get_significant_uint64_count_uint(
            wide_destination.get(), coeff_count);

        // Resize destination to appropriate size
        destination.resize(max(plain_coeff_count, size_t(1)));
        destination.parms_id() = parms_id_zero;

        // Perform final multiplication by gamma inverse mod plain_modulus
        multiply_poly_scalar_coeffmod(wide_destination.get(),
            max(plain_coeff_count, size_t(1)),
            inv_gamma, plain_gamma_array[0], destination.data());
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
        size_t key_rns_poly_uint64_count = mul_safe(coeff_count,
            context_->key_context_data()->parms().coeff_modulus().size());
        size_t encrypted_size = encrypted.size();

        // Make sure we have enough secret key powers computed
        compute_secret_key_array(encrypted_size - 1);

        /*
        Decryption consists in finding c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
        as long as ||m + v|| < q_1 * q_2 * q_3
        This is equal to m + v where ||v|| is small enough.
        */

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

        auto copy_operand1(allocate_uint(coeff_count, pool));
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Initialize pointers for multiplication
            // c_1 mod qi
            const uint64_t *current_array1 = encrypted.data(1) + (i * coeff_count);
            // s mod qi
            const uint64_t *current_array2 = secret_key_array_.get() + (i * coeff_count);
            // set destination coefficients to zero modulo q_i
            set_zero_uint(coeff_count, destination.data() + (i * coeff_count));

            for (size_t j = 0; j < encrypted_size - 1; j++)
            {
                // Perform the dyadic product.
                set_uint_uint(current_array1, coeff_count, copy_operand1.get());

                // Lazy reduction
                //ntt_negacyclic_harvey_lazy(copy_operand1.get(), small_ntt_tables[i]);
                dyadic_product_coeffmod(copy_operand1.get(), current_array2, coeff_count,
                    coeff_modulus[i], copy_operand1.get());
                add_poly_poly_coeffmod(destination.data() + (i * coeff_count),
                    copy_operand1.get(), coeff_count, coeff_modulus[i],
                    destination.data() + (i * coeff_count));

                // go to c_{1+j+1} and s^{1+j+1} mod qi
                current_array1 += rns_poly_uint64_count;
                current_array2 += key_rns_poly_uint64_count;
            }

            // add c_0 into destination
            add_poly_poly_coeffmod(destination.data() + (i * coeff_count),
                encrypted.data() + (i * coeff_count), coeff_count,
                coeff_modulus[i], destination.data() + (i * coeff_count));
        }

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
        size_t coeff_count = parms.poly_modulus_degree();
        size_t coeff_mod_count = coeff_modulus.size();
        size_t rns_poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);
        size_t key_rns_poly_uint64_count = mul_safe(coeff_count,
            context_->key_context_data()->parms().coeff_modulus().size());
        size_t encrypted_size = encrypted.size();
        uint64_t plain_modulus = parms.plain_modulus().value();

        auto &small_ntt_tables = context_data.small_ntt_tables();

        // Storage for noise uint
        auto destination(allocate_uint(coeff_mod_count, pool_));

        // Storage for noise poly
        auto noise_poly(allocate_zero_poly(coeff_count, coeff_mod_count, pool_));

        // Now need to compute c(s) - Delta*m (mod q)

        // Make sure we have enough secret keys computed
        compute_secret_key_array(encrypted_size - 1);

        /*
        Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        This is equal to Delta m + v where ||v|| < Delta/2.
        */
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
        // in destination_poly.
        // Make a copy of the encryption for NTT (except the first polynomial is
        // not needed).
        auto encrypted_copy(allocate_poly(
            mul_safe(encrypted_size - 1, coeff_count), coeff_mod_count, pool_));
        set_poly_poly(encrypted.data(1), mul_safe(encrypted_size - 1, coeff_count),
            coeff_mod_count, encrypted_copy.get());

        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        auto copy_operand1(allocate_uint(coeff_count, pool_));
        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // Initialize pointers for multiplication
            const uint64_t *current_array1 = encrypted.data(1) + (i * coeff_count);
            const uint64_t *current_array2 = secret_key_array_.get() + (i * coeff_count);

            for (size_t j = 0; j < encrypted_size - 1; j++)
            {
                // Perform the dyadic product.
                set_uint_uint(current_array1, coeff_count, copy_operand1.get());

                // Lazy reduction
                ntt_negacyclic_harvey_lazy(copy_operand1.get(), small_ntt_tables[i]);

                dyadic_product_coeffmod(copy_operand1.get(), current_array2, coeff_count,
                    coeff_modulus[i], copy_operand1.get());
                add_poly_poly_coeffmod(noise_poly.get() + (i * coeff_count),
                    copy_operand1.get(),
                    coeff_count, coeff_modulus[i],
                    noise_poly.get() + (i * coeff_count));

                current_array1 += rns_poly_uint64_count;
                current_array2 += key_rns_poly_uint64_count;
            }

            // Perform inverse NTT
            inverse_ntt_negacyclic_harvey(noise_poly.get() + (i * coeff_count),
                small_ntt_tables[i]);
        }

        for (size_t i = 0; i < coeff_mod_count; i++)
        {
            // add c_0 into noise_poly
            add_poly_poly_coeffmod(noise_poly.get() + (i * coeff_count),
                encrypted.data() + (i * coeff_count), coeff_count, coeff_modulus[i],
                noise_poly.get() + (i * coeff_count));

            // Multiply by parms.plain_modulus() and reduce mod parms.coeff_modulus() to get
            // parms.coeff_modulus()*noise
            multiply_poly_scalar_coeffmod(noise_poly.get() + (i * coeff_count),
                coeff_count, plain_modulus, coeff_modulus[i],
                noise_poly.get() + (i * coeff_count));
        }

        // Compose the noise
        compose(context_data, noise_poly.get());

        // Next we compute the infinity norm mod parms.coeff_modulus()
        poly_infty_norm_coeffmod(noise_poly.get(), coeff_count, coeff_mod_count,
            context_data.total_coeff_modulus(), destination.get(), pool_);

        // The -1 accounts for scaling the invariant noise by 2
        int bit_count_diff = context_data.total_coeff_modulus_bit_count() -
            get_significant_bit_count_uint(destination.get(), coeff_mod_count) - 1;
        return max(0, bit_count_diff);
    }
}

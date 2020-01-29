// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/plaintext.h"
#include "seal/util/common.h"

using namespace std;
using namespace seal::util;

namespace seal
{
    namespace
    {
        bool is_dec_char(char c)
        {
            return c >= '0' && c <= '9';
        }

        int get_dec_value(char c)
        {
            return c - '0';
        }

        int get_coeff_length(const char *poly)
        {
            int length = 0;
            while (is_hex_char(*poly))
            {
                length++;
                poly++;
            }
            return length;
        }

        int get_coeff_power(const char *poly, int *power_length)
        {
            int length = 0;
            if (*poly == '\0')
            {
                *power_length = 0;
                return 0;
            }
            if (*poly != 'x')
            {
                return -1;
            }
            poly++;
            length++;

            if (*poly != '^')
            {
                return -1;
            }
            poly++;
            length++;

            int power = 0;
            while (is_dec_char(*poly))
            {
                power *= 10;
                power += get_dec_value(*poly);
                poly++;
                length++;
            }
            *power_length = length;
            return power;
        }

        int get_plus(const char *poly)
        {
            if (*poly == '\0')
            {
                return 0;
            }
            if (*poly++ != ' ')
            {
                return -1;
            }
            if (*poly++ != '+')
            {
                return -1;
            }
            if (*poly != ' ')
            {
                return -1;
            }
            return 3;
        }
    } // namespace

    Plaintext &Plaintext::operator=(const string &hex_poly)
    {
        if (is_ntt_form())
        {
            throw logic_error("cannot set an NTT transformed Plaintext");
        }
        if (unsigned_gt(hex_poly.size(), numeric_limits<int>::max()))
        {
            throw invalid_argument("hex_poly too long");
        }
        int length = safe_cast<int>(hex_poly.size());

        // Determine size needed to store string coefficient.
        int assign_coeff_count = 0;

        int assign_coeff_bit_count = 0;
        int pos = 0;
        int last_power = safe_cast<int>(min(data_.max_size(), safe_cast<size_t>(numeric_limits<int>::max())));
        const char *hex_poly_ptr = hex_poly.data();
        while (pos < length)
        {
            // Determine length of coefficient starting at pos.
            int coeff_length = get_coeff_length(hex_poly_ptr + pos);
            if (coeff_length == 0)
            {
                throw invalid_argument("unable to parse hex_poly");
            }

            // Determine bit length of coefficient.
            int coeff_bit_count = get_hex_string_bit_count(hex_poly_ptr + pos, coeff_length);
            if (coeff_bit_count > assign_coeff_bit_count)
            {
                assign_coeff_bit_count = coeff_bit_count;
            }
            pos += coeff_length;

            // Extract power-term.
            int power_length = 0;
            int power = get_coeff_power(hex_poly_ptr + pos, &power_length);
            if (power == -1 || power >= last_power)
            {
                throw invalid_argument("unable to parse hex_poly");
            }
            if (assign_coeff_count == 0)
            {
                assign_coeff_count = power + 1;
            }
            pos += power_length;
            last_power = power;

            // Extract plus (unless it is the end).
            int plus_length = get_plus(hex_poly_ptr + pos);
            if (plus_length == -1)
            {
                throw invalid_argument("unable to parse hex_poly");
            }
            pos += plus_length;
        }

        // If string is empty, then done.
        if (assign_coeff_count == 0 || assign_coeff_bit_count == 0)
        {
            set_zero();
            return *this;
        }

        // Resize polynomial.
        if (assign_coeff_bit_count > bits_per_uint64)
        {
            throw invalid_argument("hex_poly has too large coefficients");
        }
        resize(safe_cast<size_t>(assign_coeff_count));

        // Populate polynomial from string.
        pos = 0;
        last_power = safe_cast<int>(coeff_count());
        while (pos < length)
        {
            // Determine length of coefficient starting at pos.
            const char *coeff_start = hex_poly_ptr + pos;
            int coeff_length = get_coeff_length(coeff_start);
            pos += coeff_length;

            // Extract power-term.
            int power_length = 0;
            int power = get_coeff_power(hex_poly_ptr + pos, &power_length);
            pos += power_length;

            // Extract plus (unless it is the end).
            int plus_length = get_plus(hex_poly_ptr + pos);
            pos += plus_length;

            // Zero coefficients not set by string.
            for (int zero_power = last_power - 1; zero_power > power; --zero_power)
            {
                data_[static_cast<size_t>(zero_power)] = 0;
            }

            // Populate coefficient.
            uint64_t *coeff_ptr = data_.begin() + power;
            hex_string_to_uint(coeff_start, coeff_length, size_t(1), coeff_ptr);
            last_power = power;
        }

        // Zero coefficients not set by string.
        for (int zero_power = last_power - 1; zero_power >= 0; --zero_power)
        {
            data_[static_cast<size_t>(zero_power)] = 0;
        }

        return *this;
    }

    void Plaintext::save_members(ostream &stream) const
    {
        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            stream.write(reinterpret_cast<const char *>(&parms_id_), sizeof(parms_id_type));
            uint64_t coeff_count64 = static_cast<uint64_t>(coeff_count_);
            stream.write(reinterpret_cast<const char *>(&coeff_count64), sizeof(uint64_t));
            stream.write(reinterpret_cast<const char *>(&scale_), sizeof(double));
            data_.save(stream, compr_mode_type::none);
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);
    }

    void Plaintext::load_members(shared_ptr<SEALContext> context, istream &stream)
    {
        // Verify parameters
        if (!context)
        {
            throw invalid_argument("invalid context");
        }
        if (!context->parameters_set())
        {
            throw invalid_argument("encryption parameters are not set correctly");
        }

        Plaintext new_data(data_.pool());

        auto old_except_mask = stream.exceptions();
        try
        {
            // Throw exceptions on std::ios_base::badbit and std::ios_base::failbit
            stream.exceptions(ios_base::badbit | ios_base::failbit);

            parms_id_type parms_id{};
            stream.read(reinterpret_cast<char *>(&parms_id), sizeof(parms_id_type));

            uint64_t coeff_count64 = 0;
            stream.read(reinterpret_cast<char *>(&coeff_count64), sizeof(uint64_t));

            double scale = 0;
            stream.read(reinterpret_cast<char *>(&scale), sizeof(double));

            // Set the metadata
            new_data.parms_id_ = parms_id;
            new_data.coeff_count_ = safe_cast<size_t>(coeff_count64);
            new_data.scale_ = scale;

            // Checking the validity of loaded metadata
            // Note: We allow pure key levels here! This is to allow load_members
            // to be used also when loading derived objects like SecretKey. This
            // further means that functions reading in Plaintext objects must check
            // that for those use-cases the Plaintext truly is at the data level
            // if it is supposed to be. In other words, one cannot assume simply
            // based on load_members succeeding that the Plaintext is valid for
            // computations.
            if (!is_metadata_valid_for(new_data, context, true))
            {
                throw logic_error("plaintext data is invalid");
            }

            // Reserve memory now that the metadata is checked for validity.
            new_data.data_.reserve(new_data.coeff_count_);

            // Load the data. Note that we are supplying also the expected maximum
            // size of the loaded IntArray. This is an important security measure to
            // prevent a malformed IntArray from causing arbitrarily large memory
            // allocations.
            new_data.data_.load(stream, new_data.coeff_count_);

            // Verify that the buffer is correct
            if (!is_buffer_valid(new_data))
            {
                throw logic_error("plaintext data is invalid");
            }
        }
        catch (const ios_base::failure &)
        {
            stream.exceptions(old_except_mask);
            throw runtime_error("I/O error");
        }
        catch (...)
        {
            stream.exceptions(old_except_mask);
            throw;
        }
        stream.exceptions(old_except_mask);

        swap(*this, new_data);
    }
} // namespace seal

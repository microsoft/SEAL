// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/common.h"
#include "seal/util/pointer.h"
#include "seal/util/uintcore.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace seal
{
    namespace util
    {
        SEAL_NODISCARD inline std::string poly_to_hex_string(
            const std::uint64_t *value, std::size_t coeff_count, std::size_t coeff_uint64_count)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
#endif
            // First check if there is anything to print
            if (!coeff_count || !coeff_uint64_count)
            {
                return "0";
            }

            std::ostringstream result;
            bool empty = true;
            value += util::mul_safe(coeff_count - 1, coeff_uint64_count);
            while (coeff_count--)
            {
                if (is_zero_uint(value, coeff_uint64_count))
                {
                    value -= coeff_uint64_count;
                    continue;
                }
                if (!empty)
                {
                    result << " + ";
                }
                result << uint_to_hex_string(value, coeff_uint64_count);
                if (coeff_count)
                {
                    result << "x^" << coeff_count;
                }
                empty = false;
                value -= coeff_uint64_count;
            }
            if (empty)
            {
                result << "0";
            }
            return result.str();
        }

        SEAL_NODISCARD inline std::string poly_to_dec_string(
            const std::uint64_t *value, std::size_t coeff_count, std::size_t coeff_uint64_count, MemoryPool &pool)
        {
#ifdef SEAL_DEBUG
            if (!value)
            {
                throw std::invalid_argument("value");
            }
#endif
            // First check if there is anything to print
            if (!coeff_count || !coeff_uint64_count)
            {
                return "0";
            }

            std::ostringstream result;
            bool empty = true;
            value += coeff_count - 1;
            while (coeff_count--)
            {
                if (is_zero_uint(value, coeff_uint64_count))
                {
                    value -= coeff_uint64_count;
                    continue;
                }
                if (!empty)
                {
                    result << " + ";
                }
                result << uint_to_dec_string(value, coeff_uint64_count, pool);
                if (coeff_count)
                {
                    result << "x^" << coeff_count;
                }
                empty = false;
                value -= coeff_uint64_count;
            }
            if (empty)
            {
                result << "0";
            }
            return result.str();
        }

        SEAL_NODISCARD inline auto allocate_poly(
            std::size_t coeff_count, std::size_t coeff_uint64_count, MemoryPool &pool)
        {
            return allocate_uint(util::mul_safe(coeff_count, coeff_uint64_count), pool);
        }

        inline void set_zero_poly(std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!result && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            set_zero_uint(util::mul_safe(coeff_count, coeff_uint64_count), result);
        }

        SEAL_NODISCARD inline auto allocate_zero_poly(
            std::size_t coeff_count, std::size_t coeff_uint64_count, MemoryPool &pool)
        {
            return allocate_zero_uint(util::mul_safe(coeff_count, coeff_uint64_count), pool);
        }

        SEAL_NODISCARD inline auto allocate_poly_array(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count, MemoryPool &pool)
        {
            return allocate_uint(util::mul_safe(poly_count, coeff_count, coeff_uint64_count), pool);
        }

        inline void set_zero_poly_array(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!result && poly_count && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            set_zero_uint(util::mul_safe(poly_count, coeff_count, coeff_uint64_count), result);
        }

        SEAL_NODISCARD inline auto allocate_zero_poly_array(
            std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count, MemoryPool &pool)
        {
            return allocate_zero_uint(util::mul_safe(poly_count, coeff_count, coeff_uint64_count), pool);
        }

        inline void set_poly(
            const std::uint64_t *poly, std::size_t coeff_count, std::size_t coeff_uint64_count, std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!poly && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("poly");
            }
            if (!result && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            set_uint(poly, util::mul_safe(coeff_count, coeff_uint64_count), result);
        }

        inline void set_poly_array(
            const std::uint64_t *poly, std::size_t poly_count, std::size_t coeff_count, std::size_t coeff_uint64_count,
            std::uint64_t *result)
        {
#ifdef SEAL_DEBUG
            if (!poly && poly_count && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("poly");
            }
            if (!result && poly_count && coeff_count && coeff_uint64_count)
            {
                throw std::invalid_argument("result");
            }
#endif
            set_uint(poly, util::mul_safe(poly_count, coeff_count, coeff_uint64_count), result);
        }
    } // namespace util
} // namespace seal

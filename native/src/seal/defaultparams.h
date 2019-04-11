// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/util/globals.h"
#include "seal/smallmodulus.h"
#include "seal/util/defines.h"
#include <vector>
#include <stdexcept>
#include <map>

namespace seal
{
	/**
	Static methods for accessing default parameters.
	*/
	class DefaultParams
	{
	public:
		DefaultParams() = delete;

		/**
		Returns the default coefficients modulus for a given polynomial modulus degree.
		The polynomial modulus and the coefficient modulus obtained in this way should
		provide approdimately 128 bits of security against the best known attacks,
		assuming the standard deviation of the noise distribution is left to its default
		value.

		@param[in] poly_modulus_degree The degree of the polynomial modulus
		@throws std::out_of_range if poly_modulus_degree is not 1024, 2048, 4096, 8192, 16384, or 32768
		*/
		inline static std::vector<SmallModulus> coeff_modulus_128(std::size_t poly_modulus_degree)
		{
			try
			{
				return util::global_variables::default_coeff_modulus_128.at(poly_modulus_degree);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("no default parameters found");
			}
			return {};
		}

		/**
		Returns the default coefficients modulus for a given polynomial modulus degree.
		The polynomial modulus and the coefficient modulus obtained in this way should
		provide approdimately 192 bits of security against the best known attacks,
		assuming the standard deviation of the noise distribution is left to its default
		value.

		@param[in] poly_modulus_degree The degree of the polynomial modulus
		@throws std::out_of_range if poly_modulus_degree is not 1024, 2048, 4096, 8192, 16384, or 32768
		*/
		inline static std::vector<SmallModulus> coeff_modulus_192(std::size_t poly_modulus_degree)
		{
			try
			{
				return util::global_variables::default_coeff_modulus_192.at(poly_modulus_degree);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("no default parameters found");
			}
			return {};
		}

		/**
		Returns the default coefficients modulus for a given polynomial modulus degree.
		The polynomial modulus and the coefficient modulus obtained in this way should
		provide approdimately 256 bits of security against the best known attacks,
		assuming the standard deviation of the noise distribution is left to its default
		value.

		@param[in] poly_modulus_degree The degree of the polynomial modulus
		@throws std::out_of_range if poly_modulus_degree is not 1024, 2048, 4096, 8192, 16384, or 32768
		*/
		inline static std::vector<SmallModulus> coeff_modulus_256(std::size_t poly_modulus_degree)
		{
			try
			{
				return util::global_variables::default_coeff_modulus_256.at(poly_modulus_degree);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("no default parameters found");
			}
			return {};
		}

		/**
		Returns a 60-bit coefficient modulus prime.

		@param[in] index The list index of the prime
		@throws std::out_of_range if index is not within [0, 64)
		*/
		inline static SmallModulus small_mods_60bit(std::size_t index)
		{
			try
			{
				return util::global_variables::default_small_mods_60bit.at(index);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("index out of range");
			}
			return 0;
		}

		/**
		Returns a 50-bit coefficient modulus prime.

		@param[in] index The list index of the prime
		@throws std::out_of_range if index is not within [0, 64)
		*/
		inline static SmallModulus small_mods_50bit(std::size_t index)
		{
			try
			{
				return util::global_variables::default_small_mods_50bit.at(index);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("index out of range");
			}
			return 0;
		}

		/**
		Returns a 40-bit coefficient modulus prime.

		@param[in] index The list index of the prime
		@throws std::out_of_range if index is not within [0, 64)
		*/
		inline static SmallModulus small_mods_40bit(std::size_t index)
		{
			try
			{
				return util::global_variables::default_small_mods_40bit.at(index);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("index out of range");
			}
			return 0;
		}

		/**
		Returns a 30-bit coefficient modulus prime.

		@param[in] index The list index of the prime
		@throws std::out_of_range if index is not within [0, 64)
		*/
		inline static SmallModulus small_mods_30bit(std::size_t index)
		{
			try
			{
				return util::global_variables::default_small_mods_30bit.at(index);
			}
			catch (const std::exception &)
			{
				throw std::out_of_range("index out of range");
			}
			return 0;
		}

		/**
		Sort the coefficient modulus vector inplace for the best performance.
		The rules are:
		put the maximum prime to the last (minimize noise growth in switch_key),
		sort the rest in decreasing order (remove modular reductions in ModSwitch).
		
		@param[in] coeff_modulus The coeff_modulus vector to sort.
		*/
		inline static void sort_coeff_modulus(std::vector<SmallModulus> &coeff_modulus)
		{
			bool compare = [](const SmallModulus &a, const SmallModulus &b)
			{
				return a.value() > b.value();
			};
			std::sort(coeff_modulus.begin(), coeff_modulus.end(), compare);
			std::rotate(coeff_modulus.begin(), coeff_modulus.begin() + 1, coeff_modulus.end());
		}

		/**
    For a given poly_modulus_degree, choose the maximum 128-bit secure coeff
    modulus bit size according to HomomorphicEncryption.org, and generate
    coeff_modulus_count number of primes of similar sizes in increasing order,
		except that the maximum prime is set to the last position.
    */
    inline std::vector<SmallModulus> get_coeff_modulus(
        std::size_t poly_modulus_degree, std::size_t coeff_modulus_count)
    {
        std::size_t total_coeff_modulus_bit_count = util::global_variables::
            max_secure_coeff_modulus_bit_count.at(poly_modulus_degree);
        std::size_t count_small, bit_size_small, count_large, bit_size_large;
        bit_size_small = total_coeff_modulus_bit_count / coeff_modulus_count;
        bit_size_large = bit_size_small + 1;
        count_large = total_coeff_modulus_bit_count -
            bit_size_small * coeff_modulus_count;
        count_small = coeff_modulus_count - count_large;

        std::vector<SmallModulus> destination;
        std::vector<SmallModulus> temp;
				if (count_large)
        {
            destination = get_primes(bit_size_large, count_large, poly_modulus_degree);
        }
        if (count_small)
        {
            temp = get_primes(bit_size_small, count_small, poly_modulus_degree);
						destination.insert(destination.end(), temp.begin(), temp.end());
        }
				std::rotate(destination.begin(), destination.begin() + 1, destination.end());
    }
	};
}

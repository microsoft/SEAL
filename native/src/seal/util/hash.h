// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstdint>
#include <array>

namespace seal
{
    namespace util
    {
        class HashFunction
        {
        public:
            HashFunction() = delete;

            static constexpr std::size_t sha3_block_uint64_count = 4;

            using sha3_block_type = std::array<std::uint64_t, sha3_block_uint64_count>;

            static constexpr sha3_block_type sha3_zero_block{ { 0, 0, 0, 0 } };

            static void sha3_hash(const std::uint64_t *input, std::size_t uint64_count,
                sha3_block_type &destination);

            inline static void sha3_hash(std::uint64_t input, sha3_block_type &destination)
            {
                sha3_hash(&input, 1, destination);
            }

        private:
            static constexpr std::uint8_t sha3_round_count = 24;

            // Rate 1088 = 17 * 64 bits
            static constexpr std::uint8_t sha3_rate_uint64_count = 17;

            // Capacity 512 = 8 * 64 bits
            static constexpr std::uint8_t sha3_capacity_uint64_count = 8;

            // State size = 1600 = 25 * 64 bits
            static constexpr std::uint8_t sha3_state_uint64_count = 25;

            using sha3_state_type = std::uint64_t[5][5];

            static constexpr std::uint8_t sha3_rho[24]{
                1, 3, 6, 10, 15, 21,
                28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43,
                62, 18, 39, 61, 20, 44
            };

            static constexpr std::uint64_t sha3_round_consts[sha3_round_count]{
                0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
                0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
                0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
                0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
                0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
                0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
                0x8000000000008080, 0x0000000080000001, 0x8000000080008008
            };

            inline static std::uint64_t rot(std::uint64_t input, std::uint8_t s)
            {
                return (input << s) | (input >> (64 - s));
            }

            static void keccak_1600(sha3_state_type &state) noexcept;

            inline static void sponge_absorb(
                const std::uint64_t sha3_block[sha3_rate_uint64_count],
                sha3_state_type &state) noexcept
            {
                //for (std::uint8_t x = 0; x < 5; x++)
                //{
                //    for (std::uint8_t y = 0; y < 5; y++)
                //    {
                //        std::uint8_t index = 5 * y + x;
                //        state[x][y] ^= index < sha3_rate_uint64_count ? sha3_block[index] : std::uint64_t(0);
                //    }
                //}

                state[0][0] ^= 0 < sha3_rate_uint64_count ? sha3_block[0] : std::uint64_t(0);
                state[0][1] ^= 5 < sha3_rate_uint64_count ? sha3_block[5] : std::uint64_t(0);
                state[0][2] ^= 10 < sha3_rate_uint64_count ? sha3_block[10] : std::uint64_t(0);
                state[0][3] ^= 15 < sha3_rate_uint64_count ? sha3_block[15] : std::uint64_t(0);
                state[0][4] ^= 20 < sha3_rate_uint64_count ? sha3_block[20] : std::uint64_t(0);

                state[1][0] ^= 1 < sha3_rate_uint64_count ? sha3_block[1] : std::uint64_t(0);
                state[1][1] ^= 6 < sha3_rate_uint64_count ? sha3_block[6] : std::uint64_t(0);
                state[1][2] ^= 11 < sha3_rate_uint64_count ? sha3_block[11] : std::uint64_t(0);
                state[1][3] ^= 16 < sha3_rate_uint64_count ? sha3_block[16] : std::uint64_t(0);
                state[1][4] ^= 21 < sha3_rate_uint64_count ? sha3_block[21] : std::uint64_t(0);

                state[2][0] ^= 2 < sha3_rate_uint64_count ? sha3_block[2] : std::uint64_t(0);
                state[2][1] ^= 7 < sha3_rate_uint64_count ? sha3_block[7] : std::uint64_t(0);
                state[2][2] ^= 12 < sha3_rate_uint64_count ? sha3_block[12] : std::uint64_t(0);
                state[2][3] ^= 17 < sha3_rate_uint64_count ? sha3_block[17] : std::uint64_t(0);
                state[2][4] ^= 22 < sha3_rate_uint64_count ? sha3_block[22] : std::uint64_t(0);

                state[3][0] ^= 3 < sha3_rate_uint64_count ? sha3_block[3] : std::uint64_t(0);
                state[3][1] ^= 8 < sha3_rate_uint64_count ? sha3_block[8] : std::uint64_t(0);
                state[3][2] ^= 13 < sha3_rate_uint64_count ? sha3_block[13] : std::uint64_t(0);
                state[3][3] ^= 18 < sha3_rate_uint64_count ? sha3_block[18] : std::uint64_t(0);
                state[3][4] ^= 23 < sha3_rate_uint64_count ? sha3_block[23] : std::uint64_t(0);

                state[4][0] ^= 4 < sha3_rate_uint64_count ? sha3_block[4] : std::uint64_t(0);
                state[4][1] ^= 9 < sha3_rate_uint64_count ? sha3_block[9] : std::uint64_t(0);
                state[4][2] ^= 14 < sha3_rate_uint64_count ? sha3_block[14] : std::uint64_t(0);
                state[4][3] ^= 19 < sha3_rate_uint64_count ? sha3_block[19] : std::uint64_t(0);
                state[4][4] ^= 24 < sha3_rate_uint64_count ? sha3_block[24] : std::uint64_t(0);

                keccak_1600(state);
            }

            inline static void sponge_squeeze(const sha3_state_type &sha3_state,
                sha3_block_type &sha3_block) noexcept
            {
                // Trivial in this case: we simply output the first blocks of the state
                static_assert(sha3_block_uint64_count == 4, "sha3_block_uint64_count must equal 4");

                sha3_block[0] = sha3_state[0][0];
                sha3_block[1] = sha3_state[1][0];
                sha3_block[2] = sha3_state[2][0];
                sha3_block[3] = sha3_state[3][0];
            }
        };
    }
}
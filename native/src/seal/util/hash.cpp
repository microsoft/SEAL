// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/hash.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/pointer.h"
#include "seal/util/globals.h"
#include "seal/memorymanager.h"
#include <cstring>

using namespace std;

namespace seal
{
    namespace util
    {
        // For C++14 compatibility need to define static constexpr
        // member variables with no initialization here.
        constexpr std::uint64_t HashFunction::sha3_round_consts[sha3_round_count];

        constexpr std::uint8_t HashFunction::sha3_rho[24];

        constexpr HashFunction::sha3_block_type HashFunction::sha3_zero_block;

        void HashFunction::keccak_1600(sha3_state_type &state) noexcept
        {
            for (uint8_t round = 0; round < sha3_round_count; round++)
            {
                // theta
                uint64_t C[5];
                uint64_t D[5];
                for (uint8_t x = 0; x < 5; x++)
                {
                    C[x] = state[x][0];
                    for (uint8_t y = 1; y < 5; y++)
                    {
                        C[x] ^= state[x][y];
                    }
                }
                for (uint8_t x = 0; x < 5; x++)
                {
                    D[x] = C[(x + 4) % 5] ^ rot(C[(x + 1) % 5], 1);
                    for (uint8_t y = 0; y < 5; y++)
                    {
                        state[x][y] ^= D[x];
                    }
                }

                // rho and pi
                uint64_t ind_x = 1;
                uint64_t ind_y = 0;
                uint64_t curr = state[ind_x][ind_y];
                for (uint8_t i = 0; i < 24; i++)
                {
                    uint64_t ind_X = ind_y;
                    uint64_t ind_Y = (2 * ind_x + 3 * ind_y) % 5;
                    uint64_t temp = state[ind_X][ind_Y];
                    state[ind_X][ind_Y] = rot(curr, sha3_rho[i]);
                    curr = temp;
                    ind_x = ind_X;
                    ind_y = ind_Y;
                }

                // xi
                for (uint8_t y = 0; y < 5; y++)
                {
                    for (uint8_t x = 0; x < 5; x++)
                    {
                        C[x] = state[x][y];
                    }
                    for (uint8_t x = 0; x < 5; x++)
                    {
                        state[x][y] = C[x] ^ ((~C[(x + 1) % 5]) & C[(x + 2) % 5]);
                    }
                }

                // iota
                state[0][0] ^= sha3_round_consts[round];
            }
        }

        void HashFunction::sha3_hash(const uint64_t *input, size_t uint64_count,
            sha3_block_type &sha3_block)
        {
#ifdef SEAL_DEBUG
            if (input == nullptr)
            {
                throw invalid_argument("input cannot be null");
            }
#endif
            // Padding
            auto pool = MemoryManager::GetPool();
            size_t padded_uint64_count = sha3_rate_uint64_count * ((uint64_count / sha3_rate_uint64_count) + 1);
            auto padded_input(allocate_uint(padded_uint64_count, pool));
            set_uint_uint(input, uint64_count, padded_input.get());
            for (size_t i = uint64_count; i < padded_uint64_count; i++)
            {
                padded_input[i] = 0;
                if (i == uint64_count)
                {
                    padded_input[i] |= 0x6;
                }
                if (i == padded_uint64_count - 1)
                {
                    padded_input[i] |= uint64_t(1) << 63;
                }
            }

            // Absorb
            sha3_state_type state;
            memset(state, 0, sha3_state_uint64_count * static_cast<size_t>(bytes_per_uint64));
            for (size_t i = 0; i < padded_uint64_count; i += sha3_rate_uint64_count)
            {
                sponge_absorb(padded_input.get() + i, state);
            }

            sha3_block = sha3_zero_block;
            sponge_squeeze(state, sha3_block);
        }
    }
}

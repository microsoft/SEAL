// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"
#include <numeric>
#include <random>
#include <tuple>
#ifdef __riscv_vector
#include <riscv_vector.h>
#endif

using namespace std;

namespace seal
{
    namespace util
    {
        uint64_t exponentiate_uint_mod(uint64_t operand, uint64_t exponent, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if (modulus.is_zero())
            {
                throw invalid_argument("modulus");
            }
            if (operand >= modulus.value())
            {
                throw invalid_argument("operand");
            }
#endif
            // Fast cases
            if (exponent == 0)
            {
                // Result is supposed to be only one digit
                return 1;
            }

            if (exponent == 1)
            {
                return operand;
            }

            // Perform binary exponentiation.
            uint64_t power = operand;
            uint64_t product = 0;
            uint64_t intermediate = 1;

            // Initially: power = operand and intermediate = 1, product is irrelevant.
            while (true)
            {
                if (exponent & 1)
                {
                    product = multiply_uint_mod(power, intermediate, modulus);
                    swap(product, intermediate);
                }
                exponent >>= 1;
                if (exponent == 0)
                {
                    break;
                }
                product = multiply_uint_mod(power, power, modulus);
                swap(product, power);
            }
            return intermediate;
        }

        void divide_uint_mod_inplace(
            uint64_t *numerator, const Modulus &modulus, size_t uint64_count, uint64_t *quotient, MemoryPool &pool)
        {
            // Handle base cases
            if (uint64_count == 2)
            {
                divide_uint128_inplace(numerator, modulus.value(), quotient);
                return;
            }
            else if (uint64_count == 1)
            {
                *numerator = barrett_reduce_64(*numerator, modulus);
                *quotient = *numerator / modulus.value();
                return;
            }
            else
            {
                // If uint64_count > 2.
                // x = numerator = x1 * 2^128 + x2.
                // 2^128 = A*value + B.

                auto x1_alloc(allocate_uint(uint64_count - 2, pool));
                uint64_t *x1 = x1_alloc.get();
                uint64_t x2[2];
                auto quot_alloc(allocate_uint(uint64_count, pool));
                uint64_t *quot = quot_alloc.get();
                auto rem_alloc(allocate_uint(uint64_count, pool));
                uint64_t *rem = rem_alloc.get();
                set_uint(numerator + 2, uint64_count - 2, x1);
                set_uint(numerator, 2, x2); // x2 = (num) % 2^128.

                multiply_uint(x1, uint64_count - 2, &modulus.const_ratio()[0], 2, uint64_count, quot); // x1*A.
                multiply_uint(x1, uint64_count - 2, modulus.const_ratio()[2], uint64_count - 1, rem); // x1*B
                add_uint(rem, uint64_count - 1, x2, 2, 0, uint64_count, rem); // x1*B + x2;

                size_t remainder_uint64_count = get_significant_uint64_count_uint(rem, uint64_count);
                divide_uint_mod_inplace(rem, modulus, remainder_uint64_count, quotient, pool);
                add_uint(quotient, quot, uint64_count, quotient);
                *numerator = rem[0];

                return;
            }
        }
        #if defined(__riscv_v_intrinsic)
          
            void vector_dot_product_mod_batch(const uint64_t** temps, const uint64_t* base_row,size_t count, size_t ibase_size, const Modulus* mod,uint64_t* results_out) {
    
              uint64_t* acc_lo = new uint64_t[count]();
              uint64_t* acc_hi = new uint64_t[count]();
              
              size_t i = 0;
              while (i < count) {
                  size_t vl = __riscv_vsetvl_e64m4(count - i);
                  
                  // Vector accumulators
                  vuint64m4_t vacc_lo = __riscv_vmv_v_x_u64m4(0, vl);
                  vuint64m4_t vacc_hi = __riscv_vmv_v_x_u64m4(0, vl);
                  
                  for (size_t k = 0; k < ibase_size; k++) {
                      vuint64m4_t vbase = __riscv_vmv_v_x_u64m4(base_row[k], vl);
                      
                      // Use dynamic allocation instead of VLA
                      uint64_t* temp_vals = new uint64_t[vl];
                      
                      for (size_t j = 0; j < vl; j++) {
                          temp_vals[j] = temps[i + j][k];
                      }
                      vuint64m4_t vtemp = __riscv_vle64_v_u64m4(temp_vals, vl);
                      delete[] temp_vals;
                      
                      // Multiply
                      vuint64m4_t vlo = __riscv_vmul_vv_u64m4(vtemp, vbase, vl);
                      vuint64m4_t vhi = __riscv_vmulhu_vv_u64m4(vtemp, vbase, vl);
                      
                      // Add with carry detection
                      vuint64m4_t old_lo = vacc_lo;
                      vacc_lo = __riscv_vadd_vv_u64m4(vacc_lo, vlo, vl);
                      
                      // Correct carry detection and addition
                      vbool16_t carry = __riscv_vmsltu_vv_u64m4_b16(vacc_lo, old_lo, vl);
                      vacc_hi = __riscv_vadd_vv_u64m4(vacc_hi, vhi, vl);
                      vacc_hi = __riscv_vadd_vx_u64m4_m(carry, vacc_hi, 1, vl);  // Fixed parameter order
                  }
                  
                  // Store results
                  __riscv_vse64_v_u64m4(&acc_lo[i], vacc_lo, vl);
                  __riscv_vse64_v_u64m4(&acc_hi[i], vacc_hi, vl);
                  
                  i += vl;
              }
              
              barrett_reduce_128_batch(acc_lo, acc_hi, count, *mod, results_out);
              delete[] acc_lo;
              delete[] acc_hi;
          }
         
        #endif

        uint64_t dot_product_mod(
            const uint64_t *operand1, const uint64_t *operand2, size_t count, const Modulus &modulus)
        {
            static_assert(SEAL_MULTIPLY_ACCUMULATE_MOD_MAX >= 16, "SEAL_MULTIPLY_ACCUMULATE_MOD_MAX");
            unsigned long long accumulator[2]{ 0, 0 };
            switch (count)
            {
            case 0:
                return 0;
            case 1:
                multiply_accumulate_uint64<1>(operand1, operand2, accumulator);
                break;
            case 2:
                multiply_accumulate_uint64<2>(operand1, operand2, accumulator);
                break;
            case 3:
                multiply_accumulate_uint64<3>(operand1, operand2, accumulator);
                break;
            case 4:
                multiply_accumulate_uint64<4>(operand1, operand2, accumulator);
                break;
            case 5:
                multiply_accumulate_uint64<5>(operand1, operand2, accumulator);
                break;
            case 6:
                multiply_accumulate_uint64<6>(operand1, operand2, accumulator);
                break;
            case 7:
                multiply_accumulate_uint64<7>(operand1, operand2, accumulator);
                break;
            case 8:
                multiply_accumulate_uint64<8>(operand1, operand2, accumulator);
                break;
            case 9:
                multiply_accumulate_uint64<9>(operand1, operand2, accumulator);
                break;
            case 10:
                multiply_accumulate_uint64<10>(operand1, operand2, accumulator);
                break;
            case 11:
                multiply_accumulate_uint64<11>(operand1, operand2, accumulator);
                break;
            case 12:
                multiply_accumulate_uint64<12>(operand1, operand2, accumulator);
                break;
            case 13:
                multiply_accumulate_uint64<13>(operand1, operand2, accumulator);
                break;
            case 14:
                multiply_accumulate_uint64<14>(operand1, operand2, accumulator);
                break;
            case 15:
                multiply_accumulate_uint64<15>(operand1, operand2, accumulator);
                break;
            case 16:
            largest_case:
                multiply_accumulate_uint64<16>(operand1, operand2, accumulator);
                break;
            default:
                accumulator[0] = dot_product_mod(operand1 + 16, operand2 + 16, count - 16, modulus);
                goto largest_case;
            };
            return barrett_reduce_128(accumulator, modulus);
        }
    } // namespace util
} // namespace seal

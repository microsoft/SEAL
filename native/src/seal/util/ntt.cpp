// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/ntt.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <algorithm>

using namespace std;

namespace seal
{
    namespace util
    {
        NTTTables::NTTTables(int coeff_count_power, const Modulus &modulus, MemoryPoolHandle pool) : pool_(move(pool))
        {
#ifdef SEAL_DEBUG
            if (!pool_)
            {
                throw invalid_argument("pool is uninitialized");
            }
#endif
            initialize(coeff_count_power, modulus);
        }

        void NTTTables::initialize(int coeff_count_power, const Modulus &modulus)
        {
#ifdef SEAL_DEBUG
            if ((coeff_count_power < get_power_of_two(SEAL_POLY_MOD_DEGREE_MIN)) ||
                coeff_count_power > get_power_of_two(SEAL_POLY_MOD_DEGREE_MAX))
            {
                throw invalid_argument("coeff_count_power out of range");
            }
#endif
            coeff_count_power_ = coeff_count_power;
            coeff_count_ = size_t(1) << coeff_count_power_;

            // Allocate memory for the tables
            root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            modulus_ = modulus;

            // We defer parameter checking to try_minimal_primitive_root(...)
            if (!try_minimal_primitive_root(2 * coeff_count_, modulus_, root_))
            {
                throw invalid_argument("invalid modulus");
            }

            uint64_t inverse_root;
            if (!try_invert_uint_mod(root_, modulus_, inverse_root))
            {
                throw invalid_argument("invalid modulus");
            }

            // Populate the tables storing (scaled version of) powers of root
            // mod q in bit-scrambled order.
            ntt_powers_of_primitive_root(root_, root_powers_.get());

            // Populate the tables storing (scaled version of) powers of
            // (root)^{-1} mod q in bit-scrambled order.
            ntt_powers_of_primitive_root(inverse_root, inv_root_powers_.get());

            // Reordering inv_root_powers_ so that the access pattern in inverse NTT is sequential.
            auto temp = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            MultiplyUIntModOperand *temp_ptr = temp.get() + 1;
            for (size_t m = (coeff_count_ >> 1); m > 0; m >>= 1)
            {
                for (size_t i = 0; i < m; i++)
                {
                    *temp_ptr++ = inv_root_powers_[m + i];
                }
            }
            copy_n(temp.get() + 1, coeff_count_ - 1, inv_root_powers_.get() + 1);

            // Last compute n^(-1) modulo q.
            uint64_t degree_uint = static_cast<uint64_t>(coeff_count_);
            if (!try_invert_uint_mod(degree_uint, modulus_, inv_degree_modulo_.operand))
            {
                throw invalid_argument("invalid modulus");
            }
            inv_degree_modulo_.set_quotient(modulus_);

            return;
        }

        void NTTTables::ntt_powers_of_primitive_root(uint64_t root, MultiplyUIntModOperand *destination) const
        {
            MultiplyUIntModOperand *destination_start = destination;
            destination_start->set(1, modulus_);
            for (size_t i = 1; i < coeff_count_; i++)
            {
                MultiplyUIntModOperand *next_destination = destination_start + reverse_bits(i, coeff_count_power_);
                next_destination->set(multiply_uint_mod(destination->operand, root, modulus_), modulus_);
                destination = next_destination;
            }
        }

        class NTTTablesCreateIter
        {
        public:
            using value_type = NTTTables;
            using pointer = void;
            using reference = value_type;
            using difference_type = ptrdiff_t;

            // LegacyInputIterator allows reference to be equal to value_type so we can construct
            // the return objects on the fly and return by value.
            using iterator_category = input_iterator_tag;

            // Require default constructor
            NTTTablesCreateIter()
            {}

            // Other constructors
            NTTTablesCreateIter(int coeff_count_power, vector<Modulus> modulus, MemoryPoolHandle pool)
                : coeff_count_power_(coeff_count_power), modulus_(modulus), pool_(pool)
            {}

            // Require copy and move constructors and assignments
            NTTTablesCreateIter(const NTTTablesCreateIter &copy) = default;

            NTTTablesCreateIter(NTTTablesCreateIter &&source) = default;

            NTTTablesCreateIter &operator=(const NTTTablesCreateIter &assign) = default;

            NTTTablesCreateIter &operator=(NTTTablesCreateIter &&assign) = default;

            // Dereferencing creates NTTTables and returns by value
            inline value_type operator*() const
            {
                return { coeff_count_power_, modulus_[index_], pool_ };
            }

            // Pre-increment
            inline NTTTablesCreateIter &operator++() noexcept
            {
                index_++;
                return *this;
            }

            // Post-increment
            inline NTTTablesCreateIter operator++(int) noexcept
            {
                NTTTablesCreateIter result(*this);
                index_++;
                return result;
            }

            // Must be EqualityComparable
            inline bool operator==(const NTTTablesCreateIter &compare) const noexcept
            {
                return (compare.index_ == index_) && (coeff_count_power_ == compare.coeff_count_power_);
            }

            inline bool operator!=(const NTTTablesCreateIter &compare) const noexcept
            {
                return !operator==(compare);
            }

            // Arrow operator must be defined
            value_type operator->() const
            {
                return **this;
            }

        private:
            size_t index_ = 0;
            int coeff_count_power_ = 0;
            vector<Modulus> modulus_;
            MemoryPoolHandle pool_;
        };

        void CreateNTTTables(
            int coeff_count_power, const vector<Modulus> &modulus, Pointer<NTTTables> &tables, MemoryPoolHandle pool)
        {
            if (!pool)
            {
                throw invalid_argument("pool is uninitialized");
            }
            if (!modulus.size())
            {
                throw invalid_argument("invalid modulus");
            }
            // coeff_count_power and modulus will be validated by "allocate"

            NTTTablesCreateIter iter(coeff_count_power, modulus, pool);
            tables = allocate(iter, modulus.size(), pool);
        }

        /**
        This function computes in-place the negacyclic NTT. The input is
        a polynomial a of degree n in R_q, where n is assumed to be a power of
        2 and q is a prime such that q = 1 (mod 2n).

        The output is a vector A such that the following hold:
        A[j] =  a(psi**(2*bit_reverse(j) + 1)), 0 <= j < n.

        For details, see Michael Naehrig and Patrick Longa.
        */
        void ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw invalid_argument("operand");
            }
#endif
            Modulus modulus = tables.modulus();
            uint64_t two_times_modulus = modulus.value() << 1;

            // Return the NTT in scrambled order
            size_t n = size_t(1) << tables.coeff_count_power();
            size_t t = n >> 1;
            for (size_t m = 1; m < n; m <<= 1)
            {
                size_t j1 = 0;
                if (t >= 4)
                {
                    for (size_t i = 0; i < m; i++)
                    {
                        size_t j2 = j1 + t;
                        const MultiplyUIntModOperand W = tables.get_from_root_powers(m + i);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        uint64_t tx;
                        uint64_t Q;
                        for (size_t j = j1; j < j2; j += 4)
                        {
                            tx = *X - (two_times_modulus &
                                       static_cast<uint64_t>(-static_cast<int64_t>(*X >= two_times_modulus)));
                            Q = multiply_uint_mod_lazy(*Y, W, modulus);
                            *X++ = tx + Q;
                            *Y++ = tx + two_times_modulus - Q;

                            tx = *X - (two_times_modulus &
                                       static_cast<uint64_t>(-static_cast<int64_t>(*X >= two_times_modulus)));
                            Q = multiply_uint_mod_lazy(*Y, W, modulus);
                            *X++ = tx + Q;
                            *Y++ = tx + two_times_modulus - Q;

                            tx = *X - (two_times_modulus &
                                       static_cast<uint64_t>(-static_cast<int64_t>(*X >= two_times_modulus)));
                            Q = multiply_uint_mod_lazy(*Y, W, modulus);
                            *X++ = tx + Q;
                            *Y++ = tx + two_times_modulus - Q;

                            tx = *X - (two_times_modulus &
                                       static_cast<uint64_t>(-static_cast<int64_t>(*X >= two_times_modulus)));
                            Q = multiply_uint_mod_lazy(*Y, W, modulus);
                            *X++ = tx + Q;
                            *Y++ = tx + two_times_modulus - Q;
                        }
                        j1 += (t << 1);
                    }
                }
                else
                {
                    for (size_t i = 0; i < m; i++)
                    {
                        size_t j2 = j1 + t;
                        const MultiplyUIntModOperand W = tables.get_from_root_powers(m + i);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        uint64_t tx;
                        uint64_t Q;
                        for (size_t j = j1; j < j2; j++)
                        {
                            // The Harvey butterfly: assume X, Y in [0, 2p), and return X', Y' in [0, 4p).
                            // X', Y' = X + WY, X - WY (mod p).
                            tx = *X - (two_times_modulus &
                                       static_cast<uint64_t>(-static_cast<int64_t>(*X >= two_times_modulus)));
                            Q = multiply_uint_mod_lazy(*Y, W, modulus);
                            *X++ = tx + Q;
                            *Y++ = tx + two_times_modulus - Q;
                        }
                        j1 += (t << 1);
                    }
                }
                t >>= 1;
            }
        }

        // Inverse negacyclic NTT using Harvey's butterfly. (See Patrick Longa and Michael Naehrig).
        void inverse_ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_DEBUG
            if (!operand)
            {
                throw invalid_argument("operand");
            }
#endif
            Modulus modulus = tables.modulus();
            uint64_t two_times_modulus = modulus.value() << 1;

            // return the bit-reversed order of NTT.
            size_t n = size_t(1) << tables.coeff_count_power();
            size_t t = 1;
            size_t root_index = 1;
            for (size_t m = (n >> 1); m > 1; m >>= 1)
            {
                size_t j1 = 0;
                if (t >= 4)
                {
                    for (size_t i = 0; i < m; i++, root_index++)
                    {
                        size_t j2 = j1 + t;
                        const MultiplyUIntModOperand W = tables.get_from_inv_root_powers(root_index);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        uint64_t tx;
                        uint64_t ty;
                        for (size_t j = j1; j < j2; j += 4)
                        {
                            tx = *X + *Y;
                            ty = *X + two_times_modulus - *Y;
                            *X++ = tx - (two_times_modulus &
                                         static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus)));
                            *Y++ = multiply_uint_mod_lazy(ty, W, modulus);

                            tx = *X + *Y;
                            ty = *X + two_times_modulus - *Y;
                            *X++ = tx - (two_times_modulus &
                                         static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus)));
                            *Y++ = multiply_uint_mod_lazy(ty, W, modulus);

                            tx = *X + *Y;
                            ty = *X + two_times_modulus - *Y;
                            *X++ = tx - (two_times_modulus &
                                         static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus)));
                            *Y++ = multiply_uint_mod_lazy(ty, W, modulus);

                            tx = *X + *Y;
                            ty = *X + two_times_modulus - *Y;
                            *X++ = tx - (two_times_modulus &
                                         static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus)));
                            *Y++ = multiply_uint_mod_lazy(ty, W, modulus);
                        }
                        j1 += (t << 1);
                    }
                }
                else
                {
                    for (size_t i = 0; i < m; i++, root_index++)
                    {
                        size_t j2 = j1 + t;
                        const MultiplyUIntModOperand W = tables.get_from_inv_root_powers(root_index);

                        uint64_t *X = operand + j1;
                        uint64_t *Y = X + t;
                        uint64_t tx;
                        uint64_t ty;
                        for (size_t j = j1; j < j2; j++)
                        {
                            tx = *X + *Y;
                            ty = *X + two_times_modulus - *Y;
                            *X++ = tx - (two_times_modulus &
                                         static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus)));
                            *Y++ = multiply_uint_mod_lazy(ty, W, modulus);
                        }
                        j1 += (t << 1);
                    }
                }
                t <<= 1;
            }

            MultiplyUIntModOperand inv_N = tables.inv_degree_modulo();
            MultiplyUIntModOperand W = tables.get_from_inv_root_powers(root_index);
            MultiplyUIntModOperand inv_N_W;
            inv_N_W.set(multiply_uint_mod(inv_N.operand, W, modulus), modulus);

            uint64_t *X = operand;
            uint64_t *Y = X + (n >> 1);
            uint64_t tx;
            uint64_t ty;
            for (size_t j = (n >> 1); j < n; j++)
            {
                tx = *X + *Y;
                tx -= two_times_modulus & static_cast<uint64_t>(-static_cast<int64_t>(tx >= two_times_modulus));
                ty = *X + two_times_modulus - *Y;
                *X++ = multiply_uint_mod_lazy(tx, inv_N, modulus);
                *Y++ = multiply_uint_mod_lazy(ty, inv_N_W, modulus);
            }
        }
    } // namespace util
} // namespace seal

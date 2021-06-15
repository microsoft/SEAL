// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/util/ntt.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include <algorithm>

#ifdef SEAL_USE_INTEL_HEXL
#include "hexl/hexl.hpp"
#endif

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
            modulus_ = modulus;
            // We defer parameter checking to try_minimal_primitive_root(...)
            if (!try_minimal_primitive_root(2 * coeff_count_, modulus_, root_))
            {
                throw invalid_argument("invalid modulus");
            }
            if (!try_invert_uint_mod(root_, modulus_, inv_root_))
            {
                throw invalid_argument("invalid modulus");
            }

#ifdef SEAL_USE_INTEL_HEXL
            // Pre-compute HEXL NTT object
            intel::seal_ext::get_ntt(coeff_count_, modulus.value(), root_);
#endif

            // Populate tables with powers of root in specific orders.
            root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            MultiplyUIntModOperand root;
            root.set(root_, modulus_);
            uint64_t power = root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                root_powers_[reverse_bits(i, coeff_count_power_)].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            inv_root_powers_ = allocate<MultiplyUIntModOperand>(coeff_count_, pool_);
            root.set(inv_root_, modulus_);
            power = inv_root_;
            for (size_t i = 1; i < coeff_count_; i++)
            {
                inv_root_powers_[reverse_bits(i - 1, coeff_count_power_) + 1].set(power, modulus_);
                power = multiply_uint_mod(power, root, modulus_);
            }
            inv_root_powers_[0].set(static_cast<uint64_t>(1), modulus_);

            // Compute n^(-1) modulo q.
            uint64_t degree_uint = static_cast<uint64_t>(coeff_count_);
            if (!try_invert_uint_mod(degree_uint, modulus_, inv_degree_modulo_.operand))
            {
                throw invalid_argument("invalid modulus");
            }
            inv_degree_modulo_.set_quotient(modulus_);

            mod_arith_lazy_ = ModArithLazy(modulus_);
            ntt_handler_ = NTTHandler(mod_arith_lazy_);
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
                : coeff_count_power_(coeff_count_power), modulus_(modulus), pool_(move(pool))
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

        void ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();

            intel::seal_ext::compute_forward_ntt(operand, N, p, root, 4, 4);
#else
            tables.ntt_handler().transform_to_rev(
                operand.ptr(), tables.coeff_count_power(), tables.get_from_root_powers());
#endif
        }

        void inverse_ntt_negacyclic_harvey_lazy(CoeffIter operand, const NTTTables &tables)
        {
#ifdef SEAL_USE_INTEL_HEXL
            size_t N = size_t(1) << tables.coeff_count_power();
            uint64_t p = tables.modulus().value();
            uint64_t root = tables.get_root();
            intel::seal_ext::compute_inverse_ntt(operand, N, p, root, 2, 2);
#else
            MultiplyUIntModOperand inv_degree_modulo = tables.inv_degree_modulo();
            tables.ntt_handler().transform_from_rev(
                operand.ptr(), tables.coeff_count_power(), tables.get_from_inv_root_powers(), &inv_degree_modulo);
#endif
        }
    } // namespace util
} // namespace seal

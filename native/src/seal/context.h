// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/encryptionparams.h"
#include "seal/memorymanager.h"
#include "seal/modulus.h"
#include "seal/util/galois.h"
#include "seal/util/ntt.h"
#include "seal/util/numth.h"
#include "seal/util/pointer.h"
#include "seal/util/rns.h"
#include <functional>
#include <memory>
#include <unordered_map>

namespace seal
{
    /**
    Stores a set of attributes (qualifiers) of a set of encryption parameters.
    These parameters are mainly used internally in various parts of the library,
    e.g., to determine which algorithmic optimizations the current support. The
    qualifiers are automatically created by the SEALContext class, silently passed
    on to classes such as Encryptor, Evaluator, and Decryptor, and the only way to
    change them is by changing the encryption parameters themselves. In other
    words, a user will never have to create their own instance of this class, and
    in most cases never have to worry about it at all.
    */
    class EncryptionParameterQualifiers
    {
    public:
        /**
        Identifies the reason why encryption parameters are not valid.
        */
        enum class error_type : int
        {
            /**
            constructed but not yet validated
            */
            none = -1,

            /**
            valid
            */
            success = 0,

            /**
            scheme must be BFV or CKKS
            */
            invalid_scheme = 1,

            /**
            coeff_modulus's primes' count is not bounded by SEAL_COEFF_MOD_COUNT_MIN(MAX)
            */
            invalid_coeff_modulus_size = 2,

            /**
            coeff_modulus's primes' bit counts are not bounded by SEAL_USER_MOD_BIT_COUNT_MIN(MAX)
            */
            invalid_coeff_modulus_bit_count = 3,

            /**
            coeff_modulus's primes are not congruent to 1 modulo (2 * poly_modulus_degree)
            */
            invalid_coeff_modulus_no_ntt = 4,

            /**
            poly_modulus_degree is not bounded by SEAL_POLY_MOD_DEGREE_MIN(MAX)
            */
            invalid_poly_modulus_degree = 5,

            /**
            poly_modulus_degree is not a power of two
            */
            invalid_poly_modulus_degree_non_power_of_two = 6,

            /**
            parameters are too large to fit in size_t type
            */
            invalid_parameters_too_large = 7,

            /**
            parameters are not compliant with HomomorphicEncryption.org security standard
            */
            invalid_parameters_insecure = 8,

            /**
            RNSBase cannot be constructed
            */
            failed_creating_rns_base = 9,

            /**
            plain_modulus's bit count is not bounded by SEAL_PLAIN_MOD_BIT_COUNT_MIN(MAX)
            */
            invalid_plain_modulus_bit_count = 10,

            /**
            plain_modulus is not coprime to coeff_modulus
            */
            invalid_plain_modulus_coprimality = 11,

            /**
            plain_modulus is not smaller than coeff_modulus
            */
            invalid_plain_modulus_too_large = 12,

            /**
            plain_modulus is not zero
            */
            invalid_plain_modulus_nonzero = 13,

            /**
            RNSTool cannot be constructed
            */
            failed_creating_rns_tool = 14,
        };

        /**
        The variable parameter_error is set to:
        - none, if parameters are not validated;
        - success, if parameters are considered valid by Microsoft SEAL;
        - other values, if parameters are validated and invalid.
        */
        error_type parameter_error;

        /**
        Returns the name of parameter_error.
        */
        SEAL_NODISCARD const char *parameter_error_name() const noexcept;

        /**
        Returns a comprehensive message that interprets parameter_error.
        */
        SEAL_NODISCARD const char *parameter_error_message() const noexcept;

        /**
        Tells whether parameter_error is error_type::success.
        */
        SEAL_NODISCARD inline bool parameters_set() const noexcept
        {
            return parameter_error == error_type::success;
        }

        /**
        Tells whether FFT can be used for polynomial multiplication. If the
        polynomial modulus is of the form X^N+1, where N is a power of two, then
        FFT can be used for fast multiplication of polynomials modulo the polynomial
        modulus. In this case the variable using_fft will be set to true. However,
        currently Microsoft SEAL requires this to be the case for the parameters
        to be valid. Therefore, parameters_set can only be true if using_fft is
        true.
        */
        bool using_fft;

        /**
        Tells whether NTT can be used for polynomial multiplication. If the primes
        in the coefficient modulus are congruent to 1 modulo 2N, where X^N+1 is the
        polynomial modulus and N is a power of two, then the number-theoretic
        transform (NTT) can be used for fast multiplications of polynomials modulo
        the polynomial modulus and coefficient modulus. In this case the variable
        using_ntt will be set to true. However, currently Microsoft SEAL requires
        this to be the case for the parameters to be valid. Therefore, parameters_set
        can only be true if using_ntt is true.
        */
        bool using_ntt;

        /**
        Tells whether batching is supported by the encryption parameters. If the
        plaintext modulus is congruent to 1 modulo 2N, where X^N+1 is the polynomial
        modulus and N is a power of two, then it is possible to use the BatchEncoder
        class to view plaintext elements as 2-by-(N/2) matrices of integers modulo
        the plaintext modulus. This is called batching, and allows the user to
        operate on the matrix elements (slots) in a SIMD fashion, and rotate the
        matrix rows and columns. When the computation is easily vectorizable, using
        batching can yield a huge performance boost. If the encryption parameters
        support batching, the variable using_batching is set to true.
        */
        bool using_batching;

        /**
        Tells whether fast plain lift is supported by the encryption parameters.
        A certain performance optimization in multiplication of a ciphertext by
        a plaintext (Evaluator::multiply_plain) and in transforming a plaintext
        element to NTT domain (Evaluator::transform_to_ntt) can be used when the
        plaintext modulus is smaller than each prime in the coefficient modulus.
        In this case the variable using_fast_plain_lift is set to true.
        */
        bool using_fast_plain_lift;

        /**
        Tells whether the coefficient modulus consists of a set of primes that
        are in decreasing order. If this is true, certain modular reductions in
        base conversion can be omitted, improving performance.
        */
        bool using_descending_modulus_chain;

        /**
        Tells whether the encryption parameters are secure based on the standard
        parameters from HomomorphicEncryption.org security standard.
        */
        sec_level_type sec_level;

    private:
        EncryptionParameterQualifiers()
            : parameter_error(error_type::none), using_fft(false), using_ntt(false), using_batching(false),
              using_fast_plain_lift(false), using_descending_modulus_chain(false), sec_level(sec_level_type::none)
        {}

        friend class SEALContext;
    };

    /**
    Performs sanity checks (validation) and pre-computations for a given set of encryption
    parameters. While the EncryptionParameters class is intended to be a light-weight class
    to store the encryption parameters, the SEALContext class is a heavy-weight class that
    is constructed from a given set of encryption parameters. It validates the parameters
    for correctness, evaluates their properties, and performs and stores the results of
    several costly pre-computations.

    After the user has set at least the poly_modulus, coeff_modulus, and plain_modulus
    parameters in a given EncryptionParameters instance, the parameters can be validated
    for correctness and functionality by constructing an instance of SEALContext. The
    constructor of SEALContext does all of its work automatically, and concludes by
    constructing and storing an instance of the EncryptionParameterQualifiers class, with
    its flags set according to the properties of the given parameters. If the created
    instance of EncryptionParameterQualifiers has the parameters_set flag set to true, the
    given parameter set has been deemed valid and is ready to be used. If the parameters
    were for some reason not appropriately set, the parameters_set flag will be false,
    and a new SEALContext will have to be created after the parameters are corrected.

    By default, SEALContext creates a chain of SEALContext::ContextData instances. The
    first one in the chain corresponds to special encryption parameters that are reserved
    to be used by the various key classes (SecretKey, PublicKey, etc.). These are the exact
    same encryption parameters that are created by the user and passed to th constructor of
    SEALContext. The functions key_context_data() and key_parms_id() return the ContextData
    and the parms_id corresponding to these special parameters. The rest of the ContextData
    instances in the chain correspond to encryption parameters that are derived from the
    first encryption parameters by always removing the last one of the moduli in the
    coeff_modulus, until the resulting parameters are no longer valid, e.g., there are no
    more primes left. These derived encryption parameters are used by ciphertexts and
    plaintexts and their respective ContextData can be accessed through the
    get_context_data(parms_id_type) function. The functions first_context_data() and
    last_context_data() return the ContextData corresponding to the first and the last
    set of parameters in the "data" part of the chain, i.e., the second and the last element
    in the full chain. The chain itself is a doubly linked list, and is referred to as the
    modulus switching chain.

    @see EncryptionParameters for more details on the parameters.
    @see EncryptionParameterQualifiers for more details on the qualifiers.
    */
    class SEALContext
    {
    public:
        /**
        Class to hold pre-computation data for a given set of encryption parameters.
        */
        class ContextData
        {
            friend class SEALContext;

        public:
            ContextData() = delete;

            ContextData(const ContextData &copy) = delete;

            ContextData(ContextData &&move) = default;

            ContextData &operator=(ContextData &&move) = default;

            /**
            Returns a const reference to the underlying encryption parameters.
            */
            SEAL_NODISCARD inline auto &parms() const noexcept
            {
                return parms_;
            }

            /**
            Returns the parms_id of the current parameters.
            */
            SEAL_NODISCARD inline auto &parms_id() const noexcept
            {
                return parms_.parms_id();
            }

            /**
            Returns a copy of EncryptionParameterQualifiers corresponding to the
            current encryption parameters. Note that to change the qualifiers it is
            necessary to create a new instance of SEALContext once appropriate changes
            to the encryption parameters have been made.
            */
            SEAL_NODISCARD inline auto qualifiers() const noexcept
            {
                return qualifiers_;
            }

            /**
            Returns a pointer to a pre-computed product of all primes in the coefficient
            modulus. The security of the encryption parameters largely depends on the
            bit-length of this product, and on the degree of the polynomial modulus.
            */
            SEAL_NODISCARD inline auto total_coeff_modulus() const noexcept
            {
                return total_coeff_modulus_.get();
            }

            /**
            Returns the significant bit count of the total coefficient modulus.
            */
            SEAL_NODISCARD inline int total_coeff_modulus_bit_count() const noexcept
            {
                return total_coeff_modulus_bit_count_;
            }

            /**
            Returns a constant pointer to the RNSTool.
            */
            SEAL_NODISCARD inline auto rns_tool() const noexcept
            {
                return rns_tool_.get();
            }

            /**
            Returns a constant pointer to the NTT tables.
            */
            SEAL_NODISCARD inline auto small_ntt_tables() const noexcept
            {
                return small_ntt_tables_.get();
            }

            /**
            Returns a constant pointer to the NTT tables.
            */
            SEAL_NODISCARD inline auto plain_ntt_tables() const noexcept
            {
                return plain_ntt_tables_.get();
            }

            /**
            Returns a constant pointer to the GaloisTool.
            */
            SEAL_NODISCARD inline auto galois_tool() const noexcept
            {
                return galois_tool_.get();
            }

            /**
            Return a pointer to BFV "Delta", i.e. coefficient modulus divided by
            plaintext modulus.
            */
            SEAL_NODISCARD inline auto coeff_div_plain_modulus() const noexcept
            {
                return coeff_div_plain_modulus_.get();
            }

            /**
            Return the threshold for the upper half of integers modulo plain_modulus.
            This is simply (plain_modulus + 1) / 2.
            */
            SEAL_NODISCARD inline auto plain_upper_half_threshold() const noexcept
            {
                return plain_upper_half_threshold_;
            }

            /**
            Return a pointer to the plaintext upper half increment, i.e. coeff_modulus
            minus plain_modulus. The upper half increment is represented as an integer
            for the full product coeff_modulus if using_fast_plain_lift is false and is
            otherwise represented modulo each of the coeff_modulus primes in order.
            */
            SEAL_NODISCARD inline auto plain_upper_half_increment() const noexcept
            {
                return plain_upper_half_increment_.get();
            }

            /**
            Return a pointer to the upper half threshold with respect to the total
            coefficient modulus. This is needed in CKKS decryption.
            */
            SEAL_NODISCARD inline auto upper_half_threshold() const noexcept
            {
                return upper_half_threshold_.get();
            }

            /**
            Return a pointer to the upper half increment used for computing Delta*m
            and converting the coefficients to modulo coeff_modulus. For example,
            t-1 in plaintext should change into
            q - Delta = Delta*t + r_t(q) - Delta
            = Delta*(t-1) + r_t(q)
            so multiplying the message by Delta is not enough and requires also an
            addition of r_t(q). This is precisely the upper_half_increment. Note that
            this operation is only done for negative message coefficients, i.e. those
            that exceed plain_upper_half_threshold.
            */
            SEAL_NODISCARD inline auto upper_half_increment() const noexcept
            {
                return upper_half_increment_.get();
            }

            /**
            Return the non-RNS form of upper_half_increment which is q mod t.
            */
            SEAL_NODISCARD inline auto coeff_modulus_mod_plain_modulus() const noexcept -> std::uint64_t
            {
                return coeff_modulus_mod_plain_modulus_;
            }

            /**
            Returns a shared_ptr to the context data corresponding to the previous parameters
            in the modulus switching chain. If the current data is the first one in the
            chain, then the result is nullptr.
            */
            SEAL_NODISCARD inline auto prev_context_data() const noexcept
            {
                return prev_context_data_.lock();
            }

            /**
            Returns a shared_ptr to the context data corresponding to the next parameters
            in the modulus switching chain. If the current data is the last one in the
            chain, then the result is nullptr.
            */
            SEAL_NODISCARD inline auto next_context_data() const noexcept
            {
                return next_context_data_;
            }

            /**
            Returns the index of the parameter set in a chain. The initial parameters
            have index 0 and the index increases sequentially in the parameter chain.
            */
            SEAL_NODISCARD inline std::size_t chain_index() const noexcept
            {
                return chain_index_;
            }

        private:
            ContextData(EncryptionParameters parms, MemoryPoolHandle pool) : pool_(std::move(pool)), parms_(parms)
            {
                if (!pool_)
                {
                    throw std::invalid_argument("pool is uninitialized");
                }
            }

            MemoryPoolHandle pool_;

            EncryptionParameters parms_;

            EncryptionParameterQualifiers qualifiers_;

            util::Pointer<util::RNSTool> rns_tool_;

            util::Pointer<util::NTTTables> small_ntt_tables_;

            util::Pointer<util::NTTTables> plain_ntt_tables_;

            util::Pointer<util::GaloisTool> galois_tool_;

            util::Pointer<std::uint64_t> total_coeff_modulus_;

            int total_coeff_modulus_bit_count_ = 0;

            util::Pointer<util::MultiplyUIntModOperand> coeff_div_plain_modulus_;

            std::uint64_t plain_upper_half_threshold_ = 0;

            util::Pointer<std::uint64_t> plain_upper_half_increment_;

            util::Pointer<std::uint64_t> upper_half_threshold_;

            util::Pointer<std::uint64_t> upper_half_increment_;

            std::uint64_t coeff_modulus_mod_plain_modulus_ = 0;

            std::weak_ptr<const ContextData> prev_context_data_;

            std::shared_ptr<const ContextData> next_context_data_{ nullptr };

            std::size_t chain_index_ = 0;
        };

        SEALContext() = delete;

        /**
        Creates an instance of SEALContext and performs several pre-computations
        on the given EncryptionParameters.

        @param[in] parms The encryption parameters
        @param[in] expand_mod_chain Determines whether the modulus switching chain
        should be created
        @param[in] sec_level Determines whether a specific security level should be
        enforced according to HomomorphicEncryption.org security standard
        */
        SEAL_NODISCARD static auto Create(
            const EncryptionParameters &parms, bool expand_mod_chain = true,
            sec_level_type sec_level = sec_level_type::tc128)
        {
            return std::shared_ptr<SEALContext>(
                new SEALContext(parms, expand_mod_chain, sec_level, MemoryManager::GetPool()));
        }

        /**
        Returns the ContextData corresponding to encryption parameters with a given
        parms_id. If parameters with the given parms_id are not found then the
        function returns nullptr.

        @param[in] parms_id The parms_id of the encryption parameters
        */
        SEAL_NODISCARD inline auto get_context_data(parms_id_type parms_id) const
        {
            auto data = context_data_map_.find(parms_id);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to encryption parameters that are
        used for keys.
        */
        SEAL_NODISCARD inline auto key_context_data() const
        {
            auto data = context_data_map_.find(key_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to the first encryption parameters
        that are used for data.
        */
        SEAL_NODISCARD inline auto first_context_data() const
        {
            auto data = context_data_map_.find(first_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns the ContextData corresponding to the last encryption parameters
        that are used for data.
        */
        SEAL_NODISCARD inline auto last_context_data() const
        {
            auto data = context_data_map_.find(last_parms_id_);
            return (data != context_data_map_.end()) ? data->second : std::shared_ptr<ContextData>{ nullptr };
        }

        /**
        Returns whether the first_context_data's encryption parameters are valid.
        */
        SEAL_NODISCARD inline auto parameters_set() const
        {
            return first_context_data() ? first_context_data()->qualifiers_.parameters_set() : false;
        }

        /**
        Returns the name of encryption parameters' error.
        */
        SEAL_NODISCARD inline const char *parameter_error_name() const
        {
            return first_context_data() ? first_context_data()->qualifiers_.parameter_error_name()
                                        : "SEALContext is empty";
        }

        /**
        Returns a comprehensive message that interprets encryption parameters' error.
        */
        SEAL_NODISCARD inline const char *parameter_error_message() const
        {
            return first_context_data() ? first_context_data()->qualifiers_.parameter_error_message()
                                        : "SEALContext is empty";
        }

        /**
        Returns a parms_id_type corresponding to the set of encryption parameters
        that are used for keys.
        */
        SEAL_NODISCARD inline auto &key_parms_id() const noexcept
        {
            return key_parms_id_;
        }

        /**
        Returns a parms_id_type corresponding to the first encryption parameters
        that are used for data.
        */
        SEAL_NODISCARD inline auto &first_parms_id() const noexcept
        {
            return first_parms_id_;
        }

        /**
        Returns a parms_id_type corresponding to the last encryption parameters
        that are used for data.
        */
        SEAL_NODISCARD inline auto &last_parms_id() const noexcept
        {
            return last_parms_id_;
        }

        /**
        Returns whether the coefficient modulus supports keyswitching. In practice,
        support for keyswitching is required by Evaluator::relinearize,
        Evaluator::apply_galois, and all rotation and conjugation operations. For
        keyswitching to be available, the coefficient modulus parameter must consist
        of at least two prime number factors.
        */
        SEAL_NODISCARD inline bool using_keyswitching() const noexcept
        {
            return using_keyswitching_;
        }

    private:
        SEALContext(const SEALContext &copy) = delete;

        SEALContext(SEALContext &&source) = delete;

        SEALContext &operator=(const SEALContext &assign) = delete;

        SEALContext &operator=(SEALContext &&assign) = delete;

        /**
        Creates an instance of SEALContext, and performs several pre-computations
        on the given EncryptionParameters.

        @param[in] parms The encryption parameters
        @param[in] expand_mod_chain Determines whether the modulus switching chain
        should be created
        @param[in] sec_level Determines whether a specific security level should be
        enforced according to HomomorphicEncryption.org security standard
        @param[in] pool The MemoryPoolHandle pointing to a valid memory pool
        @throws std::invalid_argument if pool is uninitialized
        */
        SEALContext(EncryptionParameters parms, bool expand_mod_chain, sec_level_type sec_level, MemoryPoolHandle pool);

        ContextData validate(EncryptionParameters parms);

        /**
        Create the next context_data by dropping the last element from coeff_modulus.
        If the new encryption parameters are not valid, returns parms_id_zero.
        Otherwise, returns the parms_id of the next parameter and appends the next
        context_data to the chain.
        */
        parms_id_type create_next_context_data(const parms_id_type &prev_parms);

        MemoryPoolHandle pool_;

        parms_id_type key_parms_id_;

        parms_id_type first_parms_id_;

        parms_id_type last_parms_id_;

        std::unordered_map<parms_id_type, std::shared_ptr<const ContextData>> context_data_map_{};

        /**
        Is HomomorphicEncryption.org security standard enforced?
        */
        sec_level_type sec_level_;

        /**
        Is keyswitching supported by the encryption parameters?
        */
        bool using_keyswitching_;
    };
} // namespace seal

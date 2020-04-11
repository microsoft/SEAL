// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/context.h"
#include "seal/util/defines.h"
#include <memory>

namespace seal
{
    class Plaintext;
    class Ciphertext;
    class SecretKey;
    class PublicKey;
    class KSwitchKeys;
    class RelinKeys;
    class GaloisKeys;

    /**
    Check whether the given plaintext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    plaintext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    plaintext data itself.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    @param[in] allow_pure_key_levels Determines whether pure key levels (i.e.,
    non-data levels) should be considered valid
    */
    SEAL_NODISCARD bool is_metadata_valid_for(
        const Plaintext &in, std::shared_ptr<const SEALContext> context, bool allow_pure_key_levels = false);

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    ciphertext data itself.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    @param[in] allow_pure_key_levels Determines whether pure key levels (i.e.,
    non-data levels) should be considered valid
    */
    SEAL_NODISCARD bool is_metadata_valid_for(
        const Ciphertext &in, std::shared_ptr<const SEALContext> context, bool allow_pure_key_levels = false);

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    secret key data itself.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_metadata_valid_for(const SecretKey &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    public key data itself.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_metadata_valid_for(const PublicKey &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    KSwitchKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    KSwitchKeys data itself.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_metadata_valid_for(const KSwitchKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    RelinKeys data itself.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_metadata_valid_for(const RelinKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    GaloisKeys data itself.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_metadata_valid_for(const GaloisKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given plaintext data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the plaintext data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the plaintext data itself.

    @param[in] in The plaintext to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const Plaintext &in);

    /**
    Check whether the given ciphertext data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the ciphertext data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the ciphertext data itself.

    @param[in] in The ciphertext to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const Ciphertext &in);

    /**
    Check whether the given secret key data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the secret key data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the secret key data itself.

    @param[in] in The secret key to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const SecretKey &in);

    /**
    Check whether the given public key data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the public key data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the public key data itself.

    @param[in] in The public key to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const PublicKey &in);

    /**
    Check whether the given KSwitchKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the KSwitchKeys data itself.

    @param[in] in The KSwitchKeys to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const KSwitchKeys &in);

    /**
    Check whether the given RelinKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the RelinKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the RelinKeys data itself.

    @param[in] in The RelinKeys to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const RelinKeys &in);

    /**
    Check whether the given GaloisKeys data buffer is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the GaloisKeys data buffer does not match the SEALContext, this function
    returns false. Otherwise, returns true. This function only checks the size of
    the data buffer and not the GaloisKeys data itself.

    @param[in] in The GaloisKeys to check
    */
    SEAL_NODISCARD bool is_buffer_valid(const GaloisKeys &in);

    /**
    Check whether the given plaintext data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the plaintext data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire plaintext data buffer.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const Plaintext &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given ciphertext data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the ciphertext data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire ciphertext data buffer.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const Ciphertext &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given secret key data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the secret key data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire secret key data buffer.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const SecretKey &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given public key data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the public key data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire public key data buffer.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const PublicKey &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given KSwitchKeys data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire KSwitchKeys data buffer.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const KSwitchKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given RelinKeys data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the RelinKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire RelinKeys data buffer.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const RelinKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given GaloisKeys data is valid for a given SEALContext.
    If the given SEALContext is not set, the encryption parameters are invalid,
    or the GaloisKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow, as it checks the
    correctness of the entire GaloisKeys data buffer.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD bool is_data_valid_for(const GaloisKeys &in, std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given plaintext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    plaintext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire plaintext data buffer.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const Plaintext &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire ciphertext data buffer.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const Ciphertext &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire secret key data buffer.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const SecretKey &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire public key data buffer.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const PublicKey &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If
    the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire KSwitchKeys data buffer.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const KSwitchKeys &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire RelinKeys data buffer.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const RelinKeys &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function can be slow as it checks the validity
    of all metadata and of the entire GaloisKeys data buffer.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    SEAL_NODISCARD inline bool is_valid_for(const GaloisKeys &in, std::shared_ptr<const SEALContext> context)
    {
        return is_metadata_valid_for(in, context) && is_buffer_valid(in) && is_data_valid_for(in, context);
    }
} // namespace seal

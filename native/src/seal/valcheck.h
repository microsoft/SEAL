// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "seal/context.h"
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
    */
    bool is_metadata_valid_for(
        const Plaintext &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    ciphertext data itself.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const Ciphertext &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    secret key data itself.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const SecretKey &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    public key data itself.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const PublicKey &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    KSwitchKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    KSwitchKeys data itself.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const KSwitchKeys &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    RelinKeys data itself.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const RelinKeys &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true. This function only checks the metadata and not the
    GaloisKeys data itself.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    bool is_metadata_valid_for(
        const GaloisKeys &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given plaintext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    plaintext data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The plaintext to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const Plaintext &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given ciphertext is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    ciphertext data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The ciphertext to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const Ciphertext &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given secret key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    secret key data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The secret key to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const SecretKey &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given public key is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    public key data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The public key to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const PublicKey &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given KSwitchKeys is valid for a given SEALContext. If
    the given SEALContext is not set, the encryption parameters are invalid,
    or the KSwitchKeys data does not match the SEALContext, this function returns
    false. Otherwise, returns true.

    @param[in] in The KSwitchKeys to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const KSwitchKeys &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given RelinKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    RelinKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The RelinKeys to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const RelinKeys &in,
        std::shared_ptr<const SEALContext> context);

    /**
    Check whether the given GaloisKeys is valid for a given SEALContext. If the
    given SEALContext is not set, the encryption parameters are invalid, or the
    GaloisKeys data does not match the SEALContext, this function returns false.
    Otherwise, returns true.

    @param[in] in The GaloisKeys to check
    @param[in] context The SEALContext
    */
    bool is_valid_for(
        const GaloisKeys &in,
        std::shared_ptr<const SEALContext> context);
}
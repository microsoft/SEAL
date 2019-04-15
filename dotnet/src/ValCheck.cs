// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Static methods for object validity checking.
    /// </summary>
    public static class ValCheck
    {
        /// <summary>
        /// Check whether the given plaintext is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// plaintext data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// plaintext data itself.
        /// </summary>
        /// <param name="plaintext">The plaintext to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either plaintext or context is null</exception>
        public static bool IsMetadataValidFor(Plaintext plaintext, SEALContext context)
        {
            if (null == plaintext)
                throw new ArgumentNullException(nameof(plaintext));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_Plaintext_IsMetadataValidFor(plaintext.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given ciphertext is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// ciphertext data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// ciphertext data itself.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either ciphertext or context is null</exception>
        public static bool IsMetadataValidFor(Ciphertext ciphertext, SEALContext context)
        {
            if (null == ciphertext)
                throw new ArgumentNullException(nameof(ciphertext));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_Ciphertext_IsMetadataValidFor(ciphertext.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given secret key is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// secret key data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// secret key data itself.
        /// </summary>
        /// <param name="secretKey">The secret key to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either secretKey or context is null</exception>
        public static bool IsMetadataValidFor(SecretKey secretKey, SEALContext context)
        {
            if (null == secretKey)
                throw new ArgumentNullException(nameof(secretKey));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_SecretKey_IsMetadataValidFor(secretKey.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given public key is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// public key data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// public key data itself.
        /// </summary>
        /// <param name="publicKey">The public key to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either publicKey or context is null</exception>
        public static bool IsMetadataValidFor(PublicKey publicKey, SEALContext context)
        {
            if (null == publicKey)
                throw new ArgumentNullException(nameof(publicKey));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_PublicKey_IsMetadataValidFor(publicKey.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given KSwitchKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// KSwitchKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// KSwitchKeys data itself.
        /// </summary>
        /// <param name="kswitchKeys">The KSwitchKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either kswitchKeys or context is null</exception>
        public static bool IsMetadataValidFor(KSwitchKeys kswitchKeys, SEALContext context)
        {
            if (null == kswitchKeys)
                throw new ArgumentNullException(nameof(kswitchKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_KSwitchKeys_IsMetadataValidFor(kswitchKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given RelinKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// RelinKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// RelinKeys data itself.
        /// </summary>
        /// <param name="relinKeys">The RelinKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either relinKeys or context is null</exception>
        public static bool IsMetadataValidFor(RelinKeys relinKeys, SEALContext context)
        {
            if (null == relinKeys)
                throw new ArgumentNullException(nameof(relinKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_RelinKeys_IsMetadataValidFor(relinKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given GaloisKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// GaloisKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true. This function only checks the metadata and not the
        /// GaloisKeys data itself.
        /// </summary>
        /// <param name="galoisKeys">The GaloisKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either galoisKeys or context is null</exception>
        public static bool IsMetadataValidFor(GaloisKeys galoisKeys, SEALContext context)
        {
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_GaloisKeys_IsMetadataValidFor(galoisKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given plaintext is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// plaintext data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="plaintext">The plaintext to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either plaintext or context is null</exception>
        public static bool IsValidFor(Plaintext plaintext, SEALContext context)
        {
            if (null == plaintext)
                throw new ArgumentNullException(nameof(plaintext));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_Plaintext_IsValidFor(plaintext.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given ciphertext is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// ciphertext data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either ciphertext or context is null</exception>
        public static bool IsValidFor(Ciphertext ciphertext, SEALContext context)
        {
            if (null == ciphertext)
                throw new ArgumentNullException(nameof(ciphertext));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_Ciphertext_IsValidFor(ciphertext.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given secret key is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// secret key data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="secretKey">The secret key to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either secretKey or context is null</exception>
        public static bool IsValidFor(SecretKey secretKey, SEALContext context)
        {
            if (null == secretKey)
                throw new ArgumentNullException(nameof(secretKey));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_SecretKey_IsValidFor(secretKey.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given public key is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// public key data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="publicKey">The public key to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either publicKey or context is null</exception>
        public static bool IsValidFor(PublicKey publicKey, SEALContext context)
        {
            if (null == publicKey)
                throw new ArgumentNullException(nameof(publicKey));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_PublicKey_IsValidFor(publicKey.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given KSwitchKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// KSwitchKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="kswitchKeys">The KSwitchKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either kswitchKeys or context is null</exception>
        public static bool IsValidFor(KSwitchKeys kswitchKeys, SEALContext context)
        {
            if (null == kswitchKeys)
                throw new ArgumentNullException(nameof(kswitchKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_KSwitchKeys_IsValidFor(kswitchKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given RelinKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// RelinKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="relinKeys">The RelinKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either relinKeys or context is null</exception>
        public static bool IsValidFor(RelinKeys relinKeys, SEALContext context)
        {
            if (null == relinKeys)
                throw new ArgumentNullException(nameof(relinKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_RelinKeys_IsValidFor(relinKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }

        /// <summary>
        /// Check whether the given GaloisKeys is valid for a given SEALContext. If the
        /// given SEALContext is not set, the encryption parameters are invalid, or the
        /// GaloisKeys data does not match the SEALContext, this function returns false.
        /// Otherwise, returns true.
        /// </summary>
        /// <param name="galoisKeys">The GaloisKeys to check</param>
        /// <param name="context">The SEALContext</param>
        /// <exception cref="ArgumentNullException">if either galoisKeys or context is null</exception>
        public static bool IsValidFor(GaloisKeys galoisKeys, SEALContext context)
        {
            if (null == galoisKeys)
                throw new ArgumentNullException(nameof(galoisKeys));
            if (null == context)
                throw new ArgumentNullException(nameof(context));

            NativeMethods.ValCheck_GaloisKeys_IsValidFor(galoisKeys.NativePtr, context.NativePtr, out bool result);
            return result;
        }
    }
}
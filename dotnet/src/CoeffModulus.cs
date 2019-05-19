// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Represents a standard security level according to the HomomorphicEncryption.org
    /// security standard.
    /// </summary>
    /// <remarks>
    /// Represents a standard security level according to the HomomorphicEncryption.org
    /// security standard. The value SecLevelType.None signals that no standard
    /// security level should be imposed. The value SecLevelType.TC128 provides
    /// a very high level of security and is the default security level enforced by
    /// Microsoft SEAL when constructing a SEALContext object. Normal users should not
    /// have to specify the security level explicitly anywhere.
    /// </remarks>
    public enum SecLevelType : int
    {
        /// <summary>
        /// No security level specified.
        /// </summary>
        None = 0,

        /// <summary>
        /// 128-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC128 = 128,

        /// <summary>
        /// 192-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC192 = 192,

        /// <summary>
        /// 256-bit security level according to HomomorphicEncryption.org standard.
        /// </summary>
        TC256 = 256
    }

    /// <summary>
    /// This class contains static methods for creating a coefficient modulus easily.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class contains static methods for creating a coefficient modulus easily.
    /// Note that while these functions take a SecLevelType argument, all security
    /// guarantees are lost if the output is used with encryption parameters with
    /// a mismatching value for the PolyModulusDegree.
    /// </para>
    /// <para>
    /// The default value SecLevelType.TC128 provides a very high level of security
    /// and is the default security level enforced by Microsoft SEAL when constructing
    /// a SEALContext object. Normal users should not have to specify the security
    /// level explicitly anywhere.
    /// </para>
    /// </remarks>
    public static class CoeffModulus
    {
        /// <summary>
        /// Returns the largest bit-length of the coefficient modulus, i.e., bit-length
        /// of the product of the primes in the coefficient modulus, that guarantees
        /// a given security level when using a given PolyModulusDegree, according
        /// to the HomomorphicEncryption.org security standard.
        /// </summary>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="secLevel">The desired standard security level</param>
        static public int MaxBitCount(ulong polyModulusDegree, SecLevelType secLevel)
        {
            NativeMethods.CoeffModulus_MaxBitCount(polyModulusDegree, (int)secLevel, out int result);
            return result;
        }

        /// <summary>
        /// Returns a default coefficient modulus that guarantees a given security
        /// level when using a given PolyModulusDegree, according to the
        /// HomomorphicEncryption.org security standard.
        /// </summary>
        /// <remarks>
        /// Returns a default coefficient modulus that guarantees a given security
        /// level when using a given PolyModulusDegree, according to the
        /// HomomorphicEncryption.org security standard. Note that all security
        /// guarantees are lost if the output is used with encryption parameters with
        /// a mismatching value for the PolyModulusDegree. The default parameters
        /// work well with the BFV scheme, but will usually not be optimal when using
        /// the CKKS scheme.
        /// </remarks>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="secLevel">The desired standard security level</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if secLevel is SecLevelType.None</exception>
        static public IEnumerable<SmallModulus> Default(
            ulong polyModulusDegree, SecLevelType secLevel = SecLevelType.TC128)
        {
            List<SmallModulus> result = null;

            ulong length = 0;
            NativeMethods.CoeffModulus_Default(polyModulusDegree, (int)secLevel, ref length, null);

            IntPtr[] coeffArray = new IntPtr[length];
            NativeMethods.CoeffModulus_Default(polyModulusDegree, (int)secLevel, ref length, coeffArray);

            result = new List<SmallModulus>(checked((int)length));
            foreach (IntPtr sm in coeffArray)
            {
                result.Add(new SmallModulus(sm));
            }

            return result;
        }

        /// <summary>
        /// Returns a custom coefficient modulus suitable for use with the specified
        /// PolyModulusDegree.
        /// </summary>
        /// <remarks>
        /// Returns a custom coefficient modulus suitable for use with the specified
        /// PolyModulusDegree.The return value will be a vector consisting of
        /// SmallModulus elements representing distinct prime numbers of bit-lengths
        /// as given in the bitSizes parameter. The bit sizes of the prime numbers
        /// can be at most 60 bits.
        /// </remarks>
        /// <param name="polyModulusDegree">The value of the PolyModulusDegree
        /// encryption parameter</param>
        /// <param name="bitSizes">The bit-lengths of the primes to be generated</param>
        /// <exception cref="ArgumentException">if polyModulusDegree is not
        /// a power-of-two or is too large</exception>
        /// <exception cref="ArgumentException">if bit_sizes is too large or if its
        /// elements are out of boundse</exception>
        /// <exception cref="InvalidOperationException">if not enough primes could be found</exception>
        static public IEnumerable<SmallModulus> Custom(
            ulong polyModulusDegree, IEnumerable<int> bitSizes)
        {
            if (null == bitSizes)
                throw new ArgumentNullException(nameof(bitSizes));

            List<SmallModulus> result = null;

            try
            {
                int[] bitSizesArr = bitSizes.ToArray();
                int length = bitSizesArr.Length;

                IntPtr[] coeffArray = new IntPtr[length];

                NativeMethods.CoeffModulus_Custom(polyModulusDegree, (ulong)length, bitSizesArr, coeffArray);

                result = new List<SmallModulus>(length);
                foreach (IntPtr sm in coeffArray)
                {
                    result.Add(new SmallModulus(sm));
                }
            }
            catch (COMException ex)
            {
                if ((uint)ex.HResult == NativeMethods.Errors.HRInvalidOperation)
                    throw new InvalidOperationException("Failed to find enough qualifying primes", ex);
            }

            return result;
        }
    }
}
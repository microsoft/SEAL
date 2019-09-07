// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL.Tools;
using System;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// Identify a set of Encryption Parameters
    /// </summary>
    public class ParmsId : IEquatable<ParmsId>
    {
        /// <summary>
        /// Create an instance of ParmsId
        /// </summary>
        public ParmsId()
        {
        }

        /// <summary>
        /// Create an instance of ParmsId by copying other instance
        /// </summary>
        /// <param name="other">Instance to copy</param>
        public ParmsId(ParmsId other)
        {
            if (null == other)
                throw new ArgumentNullException(nameof(other));
            CopyId(this, other.Block);
        }

        /// <summary>
        /// Create an instance of ParmsId by copying the input array
        /// </summary>
        /// <param name="id">Array to copy</param>
        private ParmsId(ulong[] id)
        {
            if (null == id)
                throw new ArgumentNullException(nameof(id));
            if (id.Length != ULongCount)
                throw new ArgumentException($"id length should be {ULongCount}");

            CopyId(this, id);
        }

        /// <summary>
        /// Array that contains the Params Id hash block
        /// </summary>
        public ulong[] Block { get; } = new ulong[4] { 0, 0, 0, 0 };

        /// <summary>
        /// Copy an input array to the ParmsId hash block
        /// </summary>
        private static void CopyId(ParmsId dest, ulong[] src)
        {
            int idx = 0;
            foreach (ulong ul in src)
            {
                dest.Block[idx++] = ul;
            }
        }

        /// <summary>
        /// Convert ParmsId to a string representation.
        /// </summary>
        public override string ToString()
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < ULongCount; i++)
            {
                byte[] bytes = BitConverter.GetBytes(Block[i]);
                for (int b = bytes.Length - 1; b >= 0; b--)
                {
                    result.Append(BitConverter.ToString(bytes, b, length: 1));
                }
                if (i < (ULongCount - 1))
                    result.Append(" ");
            }

            return result.ToString();
        }

        /// <summary>
        /// Hash code for this object
        /// </summary>
        public override int GetHashCode()
        {
            return Utilities.ComputeArrayHashCode(Block);
        }

        /// <summary>
        /// Whether the input object is equivalent to this object
        /// </summary>
        public override bool Equals(object obj)
        {
            return Equals(obj as ParmsId);
        }

        /// <summary>
        /// Whether the input object is equivalent to this object
        /// </summary>
        public bool Equals(ParmsId other)
        {
            if (null == other)
                return false;

            for (int i = 0; i < ULongCount; i++)
            {
                if (Block[i] != other.Block[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Return whether parms1 equals parms2.
        /// </summary>
        public static bool operator ==(ParmsId parms1, ParmsId parms2)
        {
            object obj1 = parms1 as object;
            object obj2 = parms2 as object;

            if (null == obj1 && null == obj2)
                return true;
            if (null == obj1)
                return false;

            return parms1.Equals(parms2);
        }

        /// <summary>
        /// Return whether parms1 does not equal parms2.
        /// </summary>
        public static bool operator !=(ParmsId parms1, ParmsId parms2)
        {
            object obj1 = parms1 as object;
            object obj2 = parms2 as object;

            if (null == obj1 && null == obj2)
                return false;
            if (null == obj1)
                return true;

            return !parms1.Equals(parms2);
        }

        /// <summary>
        /// ParmsId with a Zero hash block
        /// </summary>
        public static ParmsId Zero = new ParmsId(new ulong[4] { 0, 0, 0, 0 });

        /// <summary>
        /// Number of elements in the hash block array
        /// </summary>
        private const int ULongCount = 4;
    }
}

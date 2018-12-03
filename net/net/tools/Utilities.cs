using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;

namespace Microsoft.Research.SEAL.Tools
{
    static class Utilities
    {
        public static readonly int BitsPerUInt64 = 64;
        public static readonly int BitsPerUInt8 = 8;

        public static int DivideRoundUp(int value, int divisor)
        {
            return (value + divisor - 1) / divisor;
        }

        public static int ComputeArrayHashCode(ulong[] array)
        {
            int hash_seed = 17;
            int hash_multiply = 23;

            int hash = hash_seed;

            for (int i = 0; i < array.Length; i++)
            {
                ulong value = array[i];
                if (value != 0)
                {
                    hash *= hash_multiply;
                    hash += (int)value;
                    value >>= 32;
                    hash *= hash_multiply;
                    hash += (int)value;
                }
            }

            return hash;
        }
    }
}

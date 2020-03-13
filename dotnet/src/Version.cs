// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Text;

namespace Microsoft.Research.SEAL
{
    /// <summary>
    /// This class contains static methods for retrieving Microsoft SEAL's version numbers.
    /// </summary>
    /// <remark>
    /// Use the name SEALVersion to distinguish it from System.Version.
    /// </remark>
    public static class SEALVersion
    {
        /// <summary>
        /// Returns Microsoft SEAL's major version number.
        /// </summary>
        static public byte Major()
        {
            NativeMethods.Version_Major(out byte result);
            return result;
        }

        /// <summary>
        /// Returns Microsoft SEAL's minor version number.
        /// </summary>
        static public byte Minor()
        {
            NativeMethods.Version_Minor(out byte result);
            return result;
        }

        /// <summary>
        /// Returns Microsoft SEAL's patch version number.
        /// </summary>
        static public byte Patch()
        {
            NativeMethods.Version_Patch(out byte result);
            return result;
        }
    }
}
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
        /// Returns Microsoft SEAL's version number string.
        /// </summary>
        static public string Version => $"{SEALVersion.Major}.{SEALVersion.Minor}.{SEALVersion.Patch}";

        ///
        /// <summary>
        /// Returns Microsoft SEAL's major version number.
        /// </summary>
        static public byte Major
        {
            get
            {
                NativeMethods.Version_Major(out byte result);
                return result;
            }
        }

        /// <summary>
        /// Returns Microsoft SEAL's minor version number.
        /// </summary>
        static public byte Minor
        {
            get
            {
                NativeMethods.Version_Minor(out byte result);
                return result;
            }
        }

        /// <summary>
        /// Returns Microsoft SEAL's patch version number.
        /// </summary>
        static public byte Patch
        {
            get
            {
                NativeMethods.Version_Patch(out byte result);
                return result;
            }
        }
    }
}

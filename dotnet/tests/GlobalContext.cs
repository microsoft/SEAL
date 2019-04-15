// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;

namespace SEALNetTest
{
    /// <summary>
    /// Provides a global SEALContext that can be used by Tests.
    /// Necessary to run tests fast, as creating a SEALContext can take around
    /// 2 seconds.
    /// </summary>
    static class GlobalContext
    {
        static GlobalContext()
        {
            EncryptionParameters encParams = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 8192,
                CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 8192)
            };
            encParams.SetPlainModulus(65537ul);
            Context = SEALContext.Create(encParams);
        }

        public static SEALContext Context { get; private set; } = null;
    }
}

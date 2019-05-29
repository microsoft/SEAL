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
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree: 8192)
            };
            encParams.SetPlainModulus(65537ul);
            BFVContext = new SEALContext(encParams);

            encParams = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 8192,
                CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree: 8192)
            };
            CKKSContext = new SEALContext(encParams);
        }

        public static SEALContext BFVContext { get; private set; } = null;
        public static SEALContext CKKSContext { get; private set; } = null;
    }
}

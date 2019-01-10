using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class EncryptionParameterQualifiersTests
    {
        [TestMethod]
        public void SomeTest()
        {
            SEALContext context = GlobalContext.Context;

            Assert.IsTrue(context.FirstContextData.Qualifiers.ParametersSet);
            Assert.IsFalse(context.FirstContextData.Qualifiers.UsingBatching);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingFFT);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingHEStdSecurity);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingNTT);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 4096,
                CoeffModulus = DefaultParams.CoeffModulus128(4096)
            };

            SEALContext context2 = SEALContext.Create(parms);

            Assert.IsTrue(context2.FirstContextData.Qualifiers.ParametersSet);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingBatching);
            Assert.IsFalse(context2.FirstContextData.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingFFT);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingHEStdSecurity);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingNTT);
        }
    }
}

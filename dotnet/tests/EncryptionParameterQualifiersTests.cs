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
        public void PropertiesTest()
        {
            SEALContext context = GlobalContext.Context;

            Assert.IsTrue(context.ContextDataFirst.Qualifiers.ParametersSet);
            Assert.IsTrue(context.ContextDataFirst.Qualifiers.UsingBatching);
            Assert.IsTrue(context.ContextDataFirst.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context.ContextDataFirst.Qualifiers.UsingFFT);
            Assert.IsTrue(context.ContextDataFirst.Qualifiers.UsingHEStdSecurity);
            Assert.IsFalse(context.ContextDataFirst.Qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(context.ContextDataFirst.Qualifiers.UsingNTT);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 4096,
                CoeffModulus = DefaultParams.CoeffModulus128(4096)
            };

            SEALContext context2 = SEALContext.Create(parms);

            Assert.IsTrue(context2.ContextDataFirst.Qualifiers.ParametersSet);
            Assert.IsTrue(context2.ContextDataFirst.Qualifiers.UsingBatching);
            Assert.IsFalse(context2.ContextDataFirst.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context2.ContextDataFirst.Qualifiers.UsingFFT);
            Assert.IsTrue(context2.ContextDataFirst.Qualifiers.UsingHEStdSecurity);
            Assert.IsFalse(context.ContextDataFirst.Qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(context2.ContextDataFirst.Qualifiers.UsingNTT);

            EncryptionParameterQualifiers qualifiers = new EncryptionParameterQualifiers(context2.ContextDataFirst.Qualifiers);

            Assert.IsNotNull(qualifiers);
            Assert.IsTrue(qualifiers.ParametersSet);
            Assert.IsTrue(qualifiers.UsingBatching);
            Assert.IsFalse(qualifiers.UsingFastPlainLift);
            Assert.IsTrue(qualifiers.UsingFFT);
            Assert.IsTrue(qualifiers.UsingHEStdSecurity);
            Assert.IsFalse(qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(qualifiers.UsingNTT);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameterQualifiers epq1 = GlobalContext.Context.ContextDataFirst.Qualifiers;
            EncryptionParameterQualifiers epq2 = null;

            Assert.ThrowsException<ArgumentNullException>(() => epq2 = new EncryptionParameterQualifiers(null));
        }
    }
}

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
            SEALContext context = GlobalContext.BFVContext;

            Assert.IsTrue(context.FirstContextData.Qualifiers.ParametersSet);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingBatching);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingFFT);
            Assert.AreEqual(SecLevelType.TC128, context.FirstContextData.Qualifiers.SecLevel);
            Assert.IsFalse(context.FirstContextData.Qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(context.FirstContextData.Qualifiers.UsingNTT);
            Assert.IsTrue(context.UsingKeyswitching);

            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 4096,
                CoeffModulus = CoeffModulus.BFVDefault(4096)
            };

            SEALContext context2 = new SEALContext(parms);

            Assert.IsTrue(context2.FirstContextData.Qualifiers.ParametersSet);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingBatching);
            Assert.IsFalse(context2.FirstContextData.Qualifiers.UsingFastPlainLift);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingFFT);
            Assert.AreEqual(SecLevelType.TC128, context2.FirstContextData.Qualifiers.SecLevel);
            Assert.IsFalse(context.FirstContextData.Qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(context2.FirstContextData.Qualifiers.UsingNTT);
            Assert.IsTrue(context.UsingKeyswitching);

            EncryptionParameterQualifiers qualifiers = new EncryptionParameterQualifiers(context2.FirstContextData.Qualifiers);

            Assert.IsNotNull(qualifiers);
            Assert.IsTrue(qualifiers.ParametersSet);
            Assert.IsTrue(qualifiers.UsingBatching);
            Assert.IsFalse(qualifiers.UsingFastPlainLift);
            Assert.IsTrue(qualifiers.UsingFFT);
            Assert.AreEqual(SecLevelType.TC128, qualifiers.SecLevel);
            Assert.IsTrue(qualifiers.UsingDescendingModulusChain);
            Assert.IsTrue(qualifiers.UsingNTT);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameterQualifiers epq1 = GlobalContext.BFVContext.FirstContextData.Qualifiers;
            EncryptionParameterQualifiers epq2 = null;

            Assert.ThrowsException<ArgumentNullException>(() => epq2 = new EncryptionParameterQualifiers(null));
        }
    }
}

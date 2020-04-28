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
        public void ParameterErrorTest()
        {
            SEALContext context = GlobalContext.BFVContext;
            EncryptionParameterQualifiers qualifiers = context.FirstContextData.Qualifiers;

            Assert.AreEqual(qualifiers.ParametersErrorName(), "success");
            Assert.AreEqual(qualifiers.ParametersErrorMessage(), "valid");

            EncryptionParameters encParam = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 127,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
            };
            context = new SEALContext(encParam, expandModChain: true, secLevel: SecLevelType.None);
            qualifiers = context.FirstContextData.Qualifiers;
            Assert.AreEqual(qualifiers.ParametersErrorName(), "invalid_poly_modulus_degree_non_power_of_two");
            Assert.AreEqual(qualifiers.ParametersErrorMessage(), "poly_modulus_degree is not a power of two");
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            EncryptionParameterQualifiers epq1 = GlobalContext.BFVContext.FirstContextData.Qualifiers;
            EncryptionParameterQualifiers epq2 = null;

            Utilities.AssertThrows<ArgumentNullException>(() => epq2 = new EncryptionParameterQualifiers(null));
        }
    }
}

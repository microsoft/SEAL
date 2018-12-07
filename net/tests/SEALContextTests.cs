using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class SEALContextTests
    {
        [TestMethod]
        public void ParamIDConstructorTest()
        {
            ParmsId id = new ParmsId();

            Assert.AreEqual(0ul, id.Block[0]);
            Assert.AreEqual(0ul, id.Block[1]);
            Assert.AreEqual(0ul, id.Block[2]);
            Assert.AreEqual(0ul, id.Block[3]);

            id.Block[0] = 5;
            id.Block[1] = 4;
            id.Block[2] = 3;
            id.Block[3] = 2;

            ParmsId id2 = new ParmsId(id);

            id.Block[1] = 7;

            Assert.AreEqual(5ul, id2.Block[0]);
            Assert.AreEqual(4ul, id2.Block[1]);
            Assert.AreEqual(3ul, id2.Block[2]);
            Assert.AreEqual(2ul, id2.Block[3]);
            Assert.AreEqual(7ul, id.Block[1]);
        }

        [TestMethod]
        public void SEALContextCreateTest()
        {
            EncryptionParameters encParams1 = new EncryptionParameters(SchemeType.BFV);
            EncryptionParameters encParams2 = new EncryptionParameters(SchemeType.CKKS);

            SEALContext context1 = SEALContext.Create(encParams1);
            SEALContext context2 = SEALContext.Create(encParams2);

            Assert.IsNotNull(context1);
            Assert.IsNotNull(context2);

            Assert.IsFalse(context1.ParametersSet);
            Assert.IsFalse(context2.ParametersSet);

            Assert.AreNotSame(context1.FirstParmsId, context1.LastParmsId);
            Assert.AreEqual(context1.FirstParmsId, context1.LastParmsId);

            SEALContext.ContextData data1 = context2.FirstContextData;
            SEALContext.ContextData data2 = context2.GetContextData(context2.FirstParmsId);

            Assert.AreNotSame(data1, data2);
            ulong[] totalCoeffMod1 = data1.TotalCoeffModulus;
            ulong[] totalCoeffMod2 = data2.TotalCoeffModulus;

            int bitCount1 = data1.TotalCoeffModulusBitCount;
            int bitCount2 = data2.TotalCoeffModulusBitCount;

            Assert.AreEqual(bitCount1, bitCount2);
            Assert.AreEqual(totalCoeffMod1.Length, totalCoeffMod2.Length);

            for (int i = 0; i < totalCoeffMod1.Length; i++)
            {
                Assert.AreEqual(totalCoeffMod1[i], totalCoeffMod2[i]);
            }
        }

        [TestMethod]
        public void SEALContextParamsTest()
        {
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods30Bit(0),
                DefaultParams.SmallMods30Bit(1),
                DefaultParams.SmallMods30Bit(2)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new SmallModulus(1 << 6),
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);

            SEALContext.ContextData data = context.FirstContextData;
            Assert.IsNotNull(data);

            EncryptionParameters parms2 = data.Parms;
            Assert.AreEqual(parms.PolyModulusDegree, parms2.PolyModulusDegree);
            Assert.AreEqual(parms.NoiseStandardDeviation, parms2.NoiseStandardDeviation);

            EncryptionParameterQualifiers qualifiers = data.Qualifiers;
            Assert.IsNotNull(qualifiers);

            Assert.IsTrue(qualifiers.ParametersSet);
            Assert.IsFalse(qualifiers.EnableBatching);
            Assert.IsTrue(qualifiers.EnableFastPlainLift);
            Assert.IsTrue(qualifiers.EnableFFT);
            Assert.IsTrue(qualifiers.EnableNTT);

            ulong[] cdpm = data.CoeffDivPlainModulus;
            Assert.AreEqual(3, cdpm.Length);

            Assert.AreEqual(32ul, data.PlainUpperHalfThreshold);

            Assert.AreEqual(3, data.PlainUpperHalfIncrement.Length);
            Assert.IsNull(data.UpperHalfThreshold);
            Assert.IsNotNull(data.UpperHalfIncrement);
            Assert.AreEqual(3, data.UpperHalfIncrement.Length);
            Assert.AreEqual(2ul, data.ChainIndex);

            SEALContext.ContextData data2 = data.NextContextData;
            Assert.IsNotNull(data2);
            Assert.AreEqual(1ul, data2.ChainIndex);

            SEALContext.ContextData data3 = data2.NextContextData;
            Assert.IsNotNull(data3);
            Assert.AreEqual(0ul, data3.ChainIndex);

            Assert.IsNull(data3.NextContextData);
        }

        [TestMethod]
        public void SEALContextCKKSParamsTest()
        {
            int slotSize = 4;
            List<SmallModulus> coeffModulus = new List<SmallModulus>
            {
                DefaultParams.SmallMods40Bit(0),
                DefaultParams.SmallMods40Bit(1),
                DefaultParams.SmallMods40Bit(2),
                DefaultParams.SmallMods40Bit(3)
            };
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = coeffModulus
            };
            SEALContext context = SEALContext.Create(parms);

            SEALContext.ContextData data = context.FirstContextData;
            Assert.IsNotNull(data);

            // This should be available in CKKS
            Assert.IsNotNull(data.UpperHalfThreshold);
            Assert.AreEqual(4, data.UpperHalfThreshold.Length);
            Assert.IsNull(data.UpperHalfIncrement);
            Assert.AreEqual(3ul, data.ChainIndex);

            SEALContext.ContextData data2 = data.NextContextData;
            Assert.IsNotNull(data2);
            Assert.AreEqual(2ul, data2.ChainIndex);

            SEALContext.ContextData data3 = data2.NextContextData;
            Assert.IsNotNull(data3);
            Assert.AreEqual(1ul, data3.ChainIndex);

            SEALContext.ContextData data4 = data3.NextContextData;
            Assert.IsNotNull(data4);
            Assert.AreEqual(0ul, data4.ChainIndex);

            Assert.IsNull(data4.NextContextData);
        }
    }
}

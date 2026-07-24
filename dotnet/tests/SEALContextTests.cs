// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class SEALContextTests
    {
        [TestMethod]
        public void SEALContextCreateTest()
        {
            EncryptionParameters encParams1 = new EncryptionParameters(SchemeType.BFV);
            EncryptionParameters encParams2 = new EncryptionParameters(SchemeType.CKKS);
            EncryptionParameters encParams3 = new EncryptionParameters(SchemeType.BGV);

            SEALContext context1 = new SEALContext(encParams1);
            SEALContext context2 = new SEALContext(encParams2);
            SEALContext context3 = new SEALContext(encParams3);

            Assert.IsNotNull(context1);
            Assert.IsNotNull(context2);
            Assert.IsNotNull(context3);

            Assert.IsFalse(context1.ParametersSet);
            Assert.IsFalse(context2.ParametersSet);
            Assert.IsFalse(context3.ParametersSet);

            Assert.AreNotSame(context1.FirstParmsId, context1.LastParmsId);
            Assert.AreEqual(context1.FirstParmsId, context1.LastParmsId);

            Assert.AreNotSame(context3.FirstParmsId, context3.LastParmsId);
            Assert.AreEqual(context3.FirstParmsId, context3.LastParmsId);

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
        public void ParameterErrorStringInteropTest()
        {
            Type nativeMethods = typeof(SEALContext).Assembly.GetType("Microsoft.Research.SEAL.NativeMethods");
            Assert.IsNotNull(nativeMethods);

            string[] methodNames =
            {
                "SEALContext_ParameterErrorName",
                "SEALContext_ParameterErrorMessage"
            };
            foreach (string methodName in methodNames)
            {
                MethodInfo method = nativeMethods.GetMethod(
                    methodName, BindingFlags.NonPublic | BindingFlags.Static);
                Assert.IsNotNull(method);
                Assert.AreEqual(typeof(StringBuilder), method.GetParameters()[1].ParameterType);

                DllImportAttribute import = method.GetCustomAttribute<DllImportAttribute>();
                Assert.IsNotNull(import);
                Assert.AreEqual(CharSet.Ansi, import.CharSet);
            }
        }

        [TestMethod]
        public void SEALContextParamsTest()
        {
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
                {
                    PolyModulusDegree = 128,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
                };
                SEALContext context = new SEALContext(parms, expandModChain: true, secLevel: SecLevelType.None);

                SEALContext.ContextData data = context.KeyContextData;
                Assert.IsNotNull(data);

                EncryptionParameters parms2 = data.Parms;
                Assert.AreEqual(parms.PolyModulusDegree, parms2.PolyModulusDegree);

                EncryptionParameterQualifiers qualifiers = data.Qualifiers;
                Assert.IsNotNull(qualifiers);

                Assert.IsTrue(qualifiers.ParametersSet);
                Assert.IsFalse(qualifiers.UsingBatching);
                Assert.IsTrue(qualifiers.UsingFastPlainLift);
                Assert.IsTrue(qualifiers.UsingFFT);
                Assert.IsTrue(qualifiers.UsingNTT);
                Assert.AreEqual(SecLevelType.None, qualifiers.SecLevel);
                Assert.IsFalse(qualifiers.UsingDescendingModulusChain);
                Assert.IsTrue(context.UsingKeyswitching);

                ulong[] cdpm = data.CoeffDivPlainModulus;
                Assert.AreEqual(3, cdpm.Length);

                Assert.AreEqual(32ul, data.PlainUpperHalfThreshold);

                Assert.AreEqual(3, data.PlainUpperHalfIncrement.Length);
                Assert.IsNull(data.UpperHalfThreshold);
                Assert.IsNotNull(data.UpperHalfIncrement);
                Assert.AreEqual(3, data.UpperHalfIncrement.Length);
                Assert.AreEqual(2ul, data.ChainIndex);

                Assert.IsNull(data.PrevContextData);
                SEALContext.ContextData data2 = data.NextContextData;
                Assert.IsNotNull(data2);
                Assert.AreEqual(1ul, data2.ChainIndex);
                Assert.AreEqual(2ul, data2.PrevContextData.ChainIndex);

                SEALContext.ContextData data3 = data2.NextContextData;
                Assert.IsNotNull(data3);
                Assert.AreEqual(0ul, data3.ChainIndex);
                Assert.AreEqual(1ul, data3.PrevContextData.ChainIndex);
                Assert.IsNull(data3.NextContextData);

                parms = new EncryptionParameters(SchemeType.BFV)
                {
                    PolyModulusDegree = 127,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
                };
                context = new SEALContext(parms, expandModChain: true, secLevel: SecLevelType.None);
                Assert.AreEqual(context.ParameterErrorName(), "invalid_poly_modulus_degree_non_power_of_two");
                Assert.AreEqual(context.ParameterErrorMessage(), "poly_modulus_degree is not a power of two");
            }
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV)
                {
                    PolyModulusDegree = 128,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
                };
                SEALContext context = new SEALContext(parms, expandModChain: true, secLevel: SecLevelType.None);

                SEALContext.ContextData data = context.KeyContextData;
                Assert.IsNotNull(data);

                EncryptionParameters parms2 = data.Parms;
                Assert.AreEqual(parms.PolyModulusDegree, parms2.PolyModulusDegree);

                EncryptionParameterQualifiers qualifiers = data.Qualifiers;
                Assert.IsNotNull(qualifiers);

                Assert.IsTrue(qualifiers.ParametersSet);
                Assert.IsFalse(qualifiers.UsingBatching);
                Assert.IsTrue(qualifiers.UsingFastPlainLift);
                Assert.IsTrue(qualifiers.UsingFFT);
                Assert.IsTrue(qualifiers.UsingNTT);
                Assert.AreEqual(SecLevelType.None, qualifiers.SecLevel);
                Assert.IsFalse(qualifiers.UsingDescendingModulusChain);
                Assert.IsTrue(context.UsingKeyswitching);

                ulong[] cdpm = data.CoeffDivPlainModulus;
                Assert.AreEqual(3, cdpm.Length);

                Assert.AreEqual(32ul, data.PlainUpperHalfThreshold);

                Assert.AreEqual(3, data.PlainUpperHalfIncrement.Length);
                Assert.IsNull(data.UpperHalfThreshold);
                Assert.IsNotNull(data.UpperHalfIncrement);
                Assert.AreEqual(3, data.UpperHalfIncrement.Length);
                Assert.AreEqual(2ul, data.ChainIndex);

                Assert.IsNull(data.PrevContextData);
                SEALContext.ContextData data2 = data.NextContextData;
                Assert.IsNotNull(data2);
                Assert.AreEqual(1ul, data2.ChainIndex);
                Assert.AreEqual(2ul, data2.PrevContextData.ChainIndex);

                SEALContext.ContextData data3 = data2.NextContextData;
                Assert.IsNotNull(data3);
                Assert.AreEqual(0ul, data3.ChainIndex);
                Assert.AreEqual(1ul, data3.PrevContextData.ChainIndex);
                Assert.IsNull(data3.NextContextData);

                parms = new EncryptionParameters(SchemeType.BGV)
                {
                    PolyModulusDegree = 127,
                    PlainModulus = new Modulus(1 << 6),
                    CoeffModulus = CoeffModulus.Create(128, new int[] { 30, 30, 30 })
                };
                context = new SEALContext(parms, expandModChain: true, secLevel: SecLevelType.None);
                Assert.AreEqual(context.ParameterErrorName(), "invalid_poly_modulus_degree_non_power_of_two");
                Assert.AreEqual(context.ParameterErrorMessage(), "poly_modulus_degree is not a power of two");
            }
        }

        [TestMethod]
        public void SEALContextCKKSParamsTest()
        {
            int slotSize = 4;
            EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = CoeffModulus.Create(2 * (ulong)slotSize, new int[] { 40, 40, 40, 40 })
            };
            SEALContext context = new SEALContext(parms,
                expandModChain: true,
                secLevel: SecLevelType.None);

            SEALContext.ContextData data = context.KeyContextData;
            Assert.IsNotNull(data);

            // This should be available in CKKS
            Assert.IsNotNull(data.UpperHalfThreshold);
            Assert.AreEqual(4, data.UpperHalfThreshold.Length);
            Assert.IsNull(data.UpperHalfIncrement);
            Assert.AreEqual(3ul, data.ChainIndex);

            Assert.IsNull(data.PrevContextData);
            SEALContext.ContextData data2 = data.NextContextData;
            Assert.IsNotNull(data2);
            Assert.AreEqual(2ul, data2.ChainIndex);
            Assert.AreEqual(3ul, data2.PrevContextData.ChainIndex);

            SEALContext.ContextData data3 = data2.NextContextData;
            Assert.IsNotNull(data3);
            Assert.AreEqual(1ul, data3.ChainIndex);
            Assert.AreEqual(2ul, data3.PrevContextData.ChainIndex);

            SEALContext.ContextData data4 = data3.NextContextData;
            Assert.IsNotNull(data4);
            Assert.AreEqual(0ul, data4.ChainIndex);
            Assert.AreEqual(1ul, data4.PrevContextData.ChainIndex);

            Assert.IsNull(data4.NextContextData);
        }

        [TestMethod]
        public void ContextDataNullPrecomputationTest()
        {
            // Valid CKKS: coeff_div_plain_modulus_ is only computed for BFV/BGV, so on
            // CKKS CoeffDivPlainModulus must report empty rather than read a null buffer.
            int slotSize = 4;
            EncryptionParameters ckksParms = new EncryptionParameters(SchemeType.CKKS)
            {
                PolyModulusDegree = 2 * (ulong)slotSize,
                CoeffModulus = CoeffModulus.Create(2 * (ulong)slotSize, new int[] { 40, 40, 40, 40 })
            };
            SEALContext ckksContext = new SEALContext(ckksParms,
                expandModChain: true,
                secLevel: SecLevelType.None);
            SEALContext.ContextData ckksData = ckksContext.KeyContextData;
            Assert.IsNotNull(ckksData);
            Assert.AreEqual(0, ckksData.CoeffDivPlainModulus.Length);

            // Failed validation with a non-empty coeff modulus leaves every precomputation
            // buffer unallocated; these accessors must report empty rather than read null.
            EncryptionParameters badParms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = new List<Modulus> { new Modulus(1ul << 60) }
            };
            SEALContext badContext = new SEALContext(badParms,
                expandModChain: false,
                secLevel: SecLevelType.None);
            Assert.IsFalse(badContext.ParametersSet);
            SEALContext.ContextData badData = badContext.KeyContextData;
            Assert.IsNotNull(badData);
            Assert.AreEqual(0, badData.TotalCoeffModulus.Length);
            Assert.AreEqual(0, badData.CoeffDivPlainModulus.Length);
            Assert.AreEqual(0, badData.PlainUpperHalfIncrement.Length);
        }

        [TestMethod]
        public void ContextDataParentLifetimeTest()
        {
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = 128,
                PlainModulus = new Modulus(1 << 6),
                CoeffModulus = CoeffModulus.Create(128, new int[] { 40, 40 })
            };

            // A ContextData holds an interior pointer into its SEALContext, so it must
            // root that context. After the only context reference goes out of scope and
            // the GC runs, reading through the ContextData must still be valid.
            SEALContext.ContextData data;
            {
                SEALContext context = new SEALContext(parms,
                    expandModChain: true, secLevel: SecLevelType.None);
                data = context.FirstContextData;
            }
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            Assert.IsTrue(data.TotalCoeffModulus.Length > 0);

            // Once the owning context is disposed the interior pointer is no longer valid,
            // so the accessor must throw rather than dereference freed native memory.
            SEALContext disposedContext = new SEALContext(parms,
                expandModChain: true, secLevel: SecLevelType.None);
            SEALContext.ContextData orphan = disposedContext.FirstContextData;
            disposedContext.Dispose();
            Assert.ThrowsException<ObjectDisposedException>(() =>
            {
                ulong[] unused = orphan.TotalCoeffModulus;
            });
        }

        [TestMethod]
        public void ExpandModChainTest()
        {
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV)
                {
                    PolyModulusDegree = 4096,
                    CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree: 4096),
                    PlainModulus = new Modulus(1 << 20)
                };

                SEALContext context1 = new SEALContext(parms,
                    expandModChain: true,
                    secLevel: SecLevelType.None);

                // By default there is a chain
                SEALContext.ContextData contextData = context1.KeyContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);
                contextData = context1.FirstContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNotNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);

                // This should not create a chain
                SEALContext context2 = new SEALContext(parms, expandModChain: false);
                contextData = context2.KeyContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);
                contextData = context2.FirstContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNotNull(contextData.PrevContextData);
                Assert.IsNull(contextData.NextContextData);
            }
            {
                EncryptionParameters parms = new EncryptionParameters(SchemeType.BGV)
                {
                    PolyModulusDegree = 4096,
                    CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree: 4096),
                    PlainModulus = new Modulus(1 << 20)
                };

                SEALContext context1 = new SEALContext(parms,
                    expandModChain: true,
                    secLevel: SecLevelType.None);

                // By default there is a chain
                SEALContext.ContextData contextData = context1.KeyContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);
                contextData = context1.FirstContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNotNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);

                // This should not create a chain
                SEALContext context2 = new SEALContext(parms, expandModChain: false);
                contextData = context2.KeyContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNull(contextData.PrevContextData);
                Assert.IsNotNull(contextData.NextContextData);
                contextData = context2.FirstContextData;
                Assert.IsNotNull(contextData);
                Assert.IsNotNull(contextData.PrevContextData);
                Assert.IsNull(contextData.NextContextData);
            }
        }
    }
}

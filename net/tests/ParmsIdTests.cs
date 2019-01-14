using Microsoft.Research.SEAL;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SEALNetTest
{
    [TestClass]
    public class ParmsIdTests
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

            Assert.IsFalse(id2.Equals(null));
            Assert.AreNotEqual(id.GetHashCode(), id2.GetHashCode());
        }

        [TestMethod]
        public void ToStringTest()
        {
            ParmsId id = new ParmsId();

            id.Block[0] = 1;
            id.Block[1] = 2;
            id.Block[2] = 3;
            id.Block[3] = 4;

            Assert.AreEqual("0000000000000001 0000000000000002 0000000000000003 0000000000000004", id.ToString());
        }

        [TestMethod]
        public void OperatorsTest()
        {
            ParmsId id = new ParmsId();

            id.Block[0] = 1;
            id.Block[1] = 2;
            id.Block[2] = 3;
            id.Block[3] = 4;

            ParmsId id2 = new ParmsId(id);

            ParmsId id3 = new ParmsId(id);
            id3.Block[0] = 2;

            Assert.IsTrue(id == id2);
            Assert.IsFalse(id == id3);

            ParmsId id_null1 = null;
            ParmsId id_null2 = null;

            Assert.IsFalse(id_null1 != id_null2);
            Assert.IsTrue(id_null1 != id);
        }

        [TestMethod]
        public void ExceptionsTest()
        {
            ParmsId id = new ParmsId();
            ParmsId id_null = null;

            Assert.ThrowsException<ArgumentNullException>(() => id = new ParmsId(id_null));

            Assert.ThrowsException<ArgumentNullException>(() => id.Load(null));
            Assert.ThrowsException<ArgumentNullException>(() => id.Save(null));
        }
    }
}

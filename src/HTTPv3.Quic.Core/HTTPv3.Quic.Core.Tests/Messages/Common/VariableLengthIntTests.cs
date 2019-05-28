using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    [TestClass]
    public class VariableLengthIntTests
    {
        [TestMethod]
        public void HappyReadTests()
        {
            var bytes = "c2 19 7c 5e ff 14 e8 8c".ToByteArrayFromHex();
            ulong expected = 151288809941952652;
            ulong actual;
            int bytesUsed;

            VariableLengthInt.ReadOne(bytes, out actual, out bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);


            bytes = "9d 7f 3e 7d".ToByteArrayFromHex();
            expected = 494878333;

            VariableLengthInt.ReadOne(bytes, out actual, out bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);


            bytes = "7b bd".ToByteArrayFromHex();
            expected = 15293;

            VariableLengthInt.ReadOne(bytes, out actual, out bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);


            bytes = "25".ToByteArrayFromHex();
            expected = 37;

            VariableLengthInt.ReadOne(bytes, out actual, out bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);


            bytes = "40 25".ToByteArrayFromHex();
            expected = 37;

            VariableLengthInt.ReadOne(bytes, out actual, out bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);
        }

        [TestMethod]
        public void HappyWriteTests()
        {
            ulong value = 151288809941952652;
            var expected = "c2 19 7c 5e ff 14 e8 8c".ToByteArrayFromHex().AsSpan();
            var actual = new byte[8].AsSpan();
            int bytesUsed;

            bytesUsed = VariableLengthInt.Write(value, ref actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);


            value = 494878333;
            expected = "9d 7f 3e 7d".ToByteArrayFromHex();
            actual = new byte[4].AsSpan();

            bytesUsed = VariableLengthInt.Write(value, ref actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);


            value = 15293;
            expected = "7b bd".ToByteArrayFromHex();
            actual = new byte[2].AsSpan();

            bytesUsed = VariableLengthInt.Write(value, ref actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);


            value = 37;
            expected = "25".ToByteArrayFromHex();
            actual = new byte[1].AsSpan();

            bytesUsed = VariableLengthInt.Write(value, ref actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void NumberTooBigTest()
        {
            ulong value = 4611686018427387904;

            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = new byte[8].AsSpan();
                VariableLengthInt.Write(value, ref bytes);
            });
        }

        [TestMethod]
        public void NotEnoughBytesToRead()
        {
            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = "c2 19 7c 5e ff 14 e8".ToByteArrayFromHex();
                ulong dummy1;
                int dummy2;
                VariableLengthInt.ReadOne(bytes, out dummy1, out dummy2);
            });

            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = "9d 7f 3e".ToByteArrayFromHex();
                ulong dummy1;
                int dummy2;
                VariableLengthInt.ReadOne(bytes, out dummy1, out dummy2);
            });

            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = "7b".ToByteArrayFromHex();
                ulong dummy1;
                int dummy2;
                VariableLengthInt.ReadOne(bytes, out dummy1, out dummy2);
            });
        }

        [TestMethod]
        public void NotEnoughBytesToWrite()
        {
            ulong value = 151288809941952652;
            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = new byte[7].AsSpan();
                VariableLengthInt.Write(value, ref bytes);
            });

            value = 494878333;
            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = new byte[3].AsSpan();
                VariableLengthInt.Write(value, ref bytes);
            });

            value = 15293;
            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = new byte[1].AsSpan();
                VariableLengthInt.Write(value, ref bytes);
            });

            value = 37;
            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var bytes = new byte[0].AsSpan();
                VariableLengthInt.Write(value, ref bytes);
            });
        }

        [TestMethod]
        public void TestGetNumberOfBytesNeeded()
        {
            Assert.AreEqual(1, VariableLengthInt.GetNumberOfBytesNeeded(0));
            Assert.AreEqual(1, VariableLengthInt.GetNumberOfBytesNeeded(63));
            Assert.AreEqual(2, VariableLengthInt.GetNumberOfBytesNeeded(64));
            Assert.AreEqual(2, VariableLengthInt.GetNumberOfBytesNeeded(16383));
            Assert.AreEqual(4, VariableLengthInt.GetNumberOfBytesNeeded(16384));
            Assert.AreEqual(4, VariableLengthInt.GetNumberOfBytesNeeded(1073741823));
            Assert.AreEqual(8, VariableLengthInt.GetNumberOfBytesNeeded(1073741824));
            Assert.AreEqual(8, VariableLengthInt.GetNumberOfBytesNeeded(4611686018427387903));
            Assert.AreEqual(0, VariableLengthInt.GetNumberOfBytesNeeded(4611686018427387904));
        }

        [TestMethod]
        public void TrySqueezingToUInt()
        {
            var bytes = "9d 7f 3e 7d".ToByteArrayFromHex();
            int expected = 494878333;

            VariableLengthInt.ReadOne(bytes, out int actual, out int bytesUsed);

            Assert.AreEqual(expected, actual);
            Assert.AreEqual(bytes.Length, bytesUsed);



            Assert.ThrowsException<ArithmeticException>(() =>
            {
                var badBytes = "c2 19 7c 5e ff 14 e8".ToByteArrayFromHex();
                int dummy1;
                int dummy2;
                VariableLengthInt.ReadOne(badBytes, out dummy1, out dummy2);
            });

        }
    }
}

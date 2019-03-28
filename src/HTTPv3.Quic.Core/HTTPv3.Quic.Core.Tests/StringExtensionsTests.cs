using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic
{
    [TestClass]
    public class StringExtensionsTests
    {
        [TestMethod]
        public void NetworkOrderedTests()
        {
            Assert.IsTrue((new byte[] { 0x00 }).SequenceEqual("00".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x00, 0x0F, 0xF0, 0xFF }).SequenceEqual("000FF0Ff".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }).SequenceEqual("0123456789aBcDeF".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE }).SequenceEqual("0123456789AbCdE".ToByteArrayFromHex()));
        }

        [TestMethod]
        public void LittleEndianOrderedTests()
        {
            Assert.IsTrue((new byte[] { 0x00 }).SequenceEqual("00".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xFF, 0xF0, 0x0F, 0x00 }).SequenceEqual("000FF0Ff".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 }).SequenceEqual("0123456789aBcDeF".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00 }).SequenceEqual("0123456789AbCdE".ToByteArrayFromHex(false)));
        }

        [TestMethod]
        public void IgnoreWhiteSpaceNetworkOrderedTests()
        {
            Assert.IsTrue((new byte[] { 0x00 }).SequenceEqual(" 0.0 ".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x00, 0x0F, 0xF0, 0xFF }).SequenceEqual("00.0F.F0.FF".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }).SequenceEqual("01234567_89ABCDEF".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[] { 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE }).SequenceEqual("0123_4567_89AB_CDE".ToByteArrayFromHex()));
        }

        [TestMethod]
        public void IgnoreWhiteSpaceLittleEndianOrderedTests()
        {
            Assert.IsTrue((new byte[] { 0x00 }).SequenceEqual(" 0.0 ".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xFF, 0xF0, 0x0F, 0x00 }).SequenceEqual("00.0F.F0.FF".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01 }).SequenceEqual("01234567_89ABCDEF".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[] { 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x00 }).SequenceEqual("0123_4567_89AB_CDE".ToByteArrayFromHex(false)));
        }

        [TestMethod]
        public void EmptyTests()
        {
            Assert.IsTrue((new byte[0]).SequenceEqual("".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[0]).SequenceEqual(" ".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[0]).SequenceEqual("  ".ToByteArrayFromHex()));
            Assert.IsTrue((new byte[0]).SequenceEqual(" . _     .".ToByteArrayFromHex()));

            Assert.IsTrue((new byte[0]).SequenceEqual("".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[0]).SequenceEqual(" ".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[0]).SequenceEqual("  ".ToByteArrayFromHex(false)));
            Assert.IsTrue((new byte[0]).SequenceEqual(" . _     .".ToByteArrayFromHex(false)));
        }

        [TestMethod]
        public void ThrowExceptionOnBadCharacters()
        {
            Assert.ThrowsException<FormatException>(() => ",".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => "g".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => "z".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => ")".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => "q0123456789ABCDEF".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => "01234567q89ABCDEF".ToByteArrayFromHex());
            Assert.ThrowsException<FormatException>(() => "0123456789ABCDEFq".ToByteArrayFromHex());
        }
    }
}

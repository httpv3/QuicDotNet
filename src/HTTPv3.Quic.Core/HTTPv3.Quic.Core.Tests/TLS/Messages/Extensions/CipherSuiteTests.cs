using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Client;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    [TestClass]
    public class CipherSuiteTests
    {
        [TestMethod]
        public void HappyClientDecodeTest()
        {
            var expected = new List<CipherSuite>();
            expected.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            expected.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            expected.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

            ReadOnlySpan<byte> data = "0006.1302.1301.1303".ToByteArrayFromHex();

            var actual = new List<CipherSuite>();
            data = data.Read(actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.IsTrue(data.IsEmpty);
        }

        [TestMethod]
        public void HappyServerDecodeTest()
        {
            var expected = CipherSuite.TLS_AES_256_GCM_SHA384;

            ReadOnlySpan<byte> data = "1302".ToByteArrayFromHex();

            data = data.Read(out CipherSuite actual);

            Assert.AreEqual(expected, actual);
            Assert.IsTrue(data.IsEmpty);
        }

        [TestMethod]
        public void NaDecodeTest()
        {
            var expected = new List<CipherSuite>();
            expected.Add(CipherSuite.NA);
            expected.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            expected.Add(CipherSuite.NA);
            expected.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            expected.Add(CipherSuite.NA);
            expected.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            expected.Add(CipherSuite.NA);
            expected.Add(CipherSuite.NA);
            ReadOnlySpan<byte> data = "0010.0000.1302.FFFF.1301.0F0F.1303.1234.4321".ToByteArrayFromHex();

            var actual = new List<CipherSuite>();
            data = data.Read(actual);

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.IsTrue(data.IsEmpty);
        }

        [TestMethod]
        public void BufferUnderrunDecodeTest()
        {
            Assert.ThrowsException<NotEnoughBytesException>(() =>
            {
                ReadOnlySpan<byte> data = "0007.1302.1301.1303".ToByteArrayFromHex();

                var list = new List<CipherSuite>();
                data.Read(list);
            });
        }

        [TestMethod]
        public void HappyClientWriteTest()
        {
            var list = new List<CipherSuite>();
            list.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            list.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            list.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            Span<byte> buffer = new byte[2000];

            var afterEncode = buffer.Write(list);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var actual = buffer.Slice(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void HappyServerWriteTest()
        {
            var expected = "1302".ToByteArrayFromHex();

            Span<byte> buffer = new byte[2000];

            var afterEncode = buffer.Write(CipherSuite.TLS_AES_256_GCM_SHA384);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var actual = buffer.Slice(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);
        }


        [TestMethod]
        public void EmptyWriteTest()
        {
            var emptyList = new List<CipherSuite>();
            var expected = "0000".ToByteArrayFromHex();

            Span<byte> buffer = new byte[2000];
            var afterEncode = buffer.Write(emptyList);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var result = buffer.Slice(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(result));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void IgnoreNaWriteTest()
        {
            var list = new List<CipherSuite>();
            list.Add(CipherSuite.NA);
            list.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            list.Add(CipherSuite.NA);
            list.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            list.Add(CipherSuite.NA);
            list.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            list.Add(CipherSuite.NA);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            Span<byte> buffer = new byte[2000];
            var afterEncode = buffer.Write(list);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var actual = buffer.Slice(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(actual));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void BufferExactTest()
        {
            var list = new List<CipherSuite>();
            list.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            list.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            list.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            Span<byte> actual = new byte[8];
            var afterEncode = actual.Write(list);
            var bytesUsed = actual.Length - afterEncode.Length;

            Assert.IsTrue(expected.SequenceEqual(actual.ToArray()));
            Assert.AreEqual(expected.Length, bytesUsed);
            Assert.IsTrue(afterEncode.IsEmpty);
        }

        [TestMethod]
        public void BufferUnderrunTest()
        {
            var list = new List<CipherSuite>();
            list.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            list.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            list.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

            Assert.ThrowsException<NotEnoughBytesException>(() => {
                Span<byte> buffer = new byte[7];
                buffer.Write(list);
            });
        }

        [TestMethod]
        public void TestParse()
        {
            Assert.AreEqual(CipherSuite.NA, CipherSuiteExtensions.ParseValue(0x0000));
            Assert.AreEqual(CipherSuite.NA, CipherSuiteExtensions.ParseValue(0x1300));
            Assert.AreEqual(CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuiteExtensions.ParseValue(0x1301));
            Assert.AreEqual(CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuiteExtensions.ParseValue(0x1302));
            Assert.AreEqual(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuiteExtensions.ParseValue(0x1303));
            Assert.AreEqual(CipherSuite.NA, CipherSuiteExtensions.ParseValue(0xFFFF));
        }
    }
}

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
        public void HappyDecodeTest()
        {
            var expected = new CipherSuites();
            expected.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            expected.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            expected.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            var data = "0006.1302.1301.1303".ToByteArrayFromHex();

            var c = new CipherSuites(data);

            Assert.IsTrue(expected.Versions.SequenceEqual(c.Versions));
        }

        [TestMethod]
        public void NaDecodeTest()
        {
            var expected = new CipherSuites();
            expected.Versions.Add(CipherSuite.NA);
            expected.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            expected.Versions.Add(CipherSuite.NA);
            expected.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            expected.Versions.Add(CipherSuite.NA);
            expected.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            expected.Versions.Add(CipherSuite.NA);
            expected.Versions.Add(CipherSuite.NA);
            var data = "0010.0000.1302.FFFF.1301.0F0F.1303.1234.4321".ToByteArrayFromHex();

            var c = new CipherSuites(data);

            Assert.IsTrue(expected.Versions.SequenceEqual(c.Versions));
        }

        [TestMethod]
        public void BufferUnderrunDecodeTest()
        {
            var data = "0007.1302.1301.1303".ToByteArrayFromHex();

            Assert.ThrowsException<NotEnoughBytesException>(() => new CipherSuites(data));
        }

        [TestMethod]
        public void HappyEncodeTest()
        {
            var input = new CipherSuites();
            input.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            input.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            input.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            var buffer = new byte[2000];
            var afterEncode = input.Encode(buffer);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var result = buffer.AsSpan(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(result));
            Assert.AreEqual(expected.Length, bytesUsed);
        }


        [TestMethod]
        public void EmptyEncodeTest()
        {
            var input = new CipherSuites();
            var expected = "0000".ToByteArrayFromHex();

            var buffer = new byte[2000];
            var afterEncode = input.Encode(buffer);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var result = buffer.AsSpan(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(result));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void IgnoreNaEncodeTest()
        {
            var input = new CipherSuites();
            input.Versions.Add(CipherSuite.NA);
            input.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            input.Versions.Add(CipherSuite.NA);
            input.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            input.Versions.Add(CipherSuite.NA);
            input.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            input.Versions.Add(CipherSuite.NA);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            var buffer = new byte[2000];
            var afterEncode = input.Encode(buffer);
            var bytesUsed = buffer.Length - afterEncode.Length;

            var result = buffer.AsSpan(0, bytesUsed).ToArray();

            Assert.IsTrue(expected.SequenceEqual(result));
            Assert.AreEqual(expected.Length, bytesUsed);
        }

        [TestMethod]
        public void BufferExactTest()
        {
            var input = new CipherSuites();
            input.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            input.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            input.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
            var expected = "0006.1302.1301.1303".ToByteArrayFromHex();

            var buffer = new byte[8];
            var afterEncode = input.Encode(buffer);
            var bytesUsed = buffer.Length - afterEncode.Length;

            Assert.IsTrue(expected.SequenceEqual(buffer));
            Assert.AreEqual(expected.Length, bytesUsed);
            Assert.IsTrue(afterEncode.IsEmpty);
        }

        [TestMethod]
        public void BufferUnderrunTest()
        {
            var input = new CipherSuites();
            input.Versions.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
            input.Versions.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
            input.Versions.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

            var buffer = new byte[7];
            Assert.ThrowsException<NotEnoughBytesException>(() => input.Encode(buffer));
        }

        [TestMethod]
        public void TestParse()
        {
            Assert.AreEqual(CipherSuite.NA, CipherSuites.ParseCipherSuite(0x0000));
            Assert.AreEqual(CipherSuite.NA, CipherSuites.ParseCipherSuite(0x1300));
            Assert.AreEqual(CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuites.ParseCipherSuite(0x1301));
            Assert.AreEqual(CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuites.ParseCipherSuite(0x1302));
            Assert.AreEqual(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, CipherSuites.ParseCipherSuite(0x1303));
            Assert.AreEqual(CipherSuite.NA, CipherSuites.ParseCipherSuite(0xFFFF));
        }
    }
}

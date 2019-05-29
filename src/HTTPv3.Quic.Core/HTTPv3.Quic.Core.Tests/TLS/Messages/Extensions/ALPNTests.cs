using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class ALPNTests
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();

            var list = new List<string>(new[] { "ASDFasdf", "", "This is only a test!" });

            foreach (var actual in list)
            {
                var afterWrite = span.WriteALPNSingle(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).ReadALPN(out string result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }

            {
                List<string> result = new List<string>();

                var afterWrite = span.WriteALPNVector(list);
                var afterRead = ((ReadOnlySpan<byte>)span).ReadALPN(result);

                Assert.IsTrue(list.SequenceEqual(result));
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
                Assert.AreEqual(2 + list.Count + list.Sum(k => k.Length), buffer.Length - afterWrite.Length);
            }
        }
    }
}

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class ProtocolVersionTests
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();

            var tests = Enum.GetValues(typeof(ProtocolVersion));
            var list = new List<ProtocolVersion>();

            foreach (var item in tests)
                list.Add((ProtocolVersion)item);

            list.Remove(ProtocolVersion.NA);

            foreach (var actual in list)
            {
                var afterWrite = span.Write(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(out ProtocolVersion result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }

            {
                List<ProtocolVersion> result = new List<ProtocolVersion>();

                var afterWrite = span.Write(list);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(result);

                Assert.IsTrue(list.SequenceEqual(result));
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
                Assert.AreEqual(1 + 2 * list.Count, buffer.Length - afterWrite.Length);
            }
        }
    }
}

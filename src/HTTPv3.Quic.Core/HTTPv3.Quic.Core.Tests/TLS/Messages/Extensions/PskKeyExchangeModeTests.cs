using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class PskKeyExchangeModeTests
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();

            var tests = Enum.GetValues(typeof(PskKeyExchangeMode));
            var list = new List<PskKeyExchangeMode>();

            foreach (var item in tests)
                list.Add((PskKeyExchangeMode)item);

            list.Remove(PskKeyExchangeMode.NA);

            foreach (var actual in list)
            {
                var afterWrite = span.Write(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(out PskKeyExchangeMode result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }

            {
                List<PskKeyExchangeMode> result = new List<PskKeyExchangeMode>();

                var afterWrite = span.Write(list);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(result);

                Assert.IsTrue(list.SequenceEqual(result));
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
                Assert.AreEqual(1 + list.Count, buffer.Length - afterWrite.Length);
            }
        }
    }
}

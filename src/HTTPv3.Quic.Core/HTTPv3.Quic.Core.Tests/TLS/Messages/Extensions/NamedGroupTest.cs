using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class NamedGroupTest
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();
            var tests = Enum.GetValues(typeof(NamedGroup));

            foreach(var test in tests)
            {
                var actual = (NamedGroup)test;
                var afterWrite = span.Write(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(out NamedGroup result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }
        }
    }
}

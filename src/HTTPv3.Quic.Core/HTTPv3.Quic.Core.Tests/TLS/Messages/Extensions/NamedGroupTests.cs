using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class NamedGroupTests
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();

            var tests = Enum.GetValues(typeof(NamedGroup));
            var list = new List<NamedGroup>();

            foreach (var item in tests)
                list.Add((NamedGroup)item);

            list.Remove(NamedGroup.NA);

            foreach (var actual in list)
            {
                var afterWrite = span.Write(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(out NamedGroup result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }

            {
                List<NamedGroup> result = new List<NamedGroup>();

                var afterWrite = span.Write(list);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(result);

                Assert.IsTrue(list.SequenceEqual(result));
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
                Assert.AreEqual(2 + 2 * list.Count, buffer.Length - afterWrite.Length);
            }
        }
    }
}

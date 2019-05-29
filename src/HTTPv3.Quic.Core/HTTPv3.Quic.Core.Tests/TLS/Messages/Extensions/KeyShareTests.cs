using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    [TestClass]
    public class KeyShareTests
    {
        [TestMethod]
        public void EasyDecodeTest()
        {
            var buffer = new byte[100];
            var span = buffer.AsSpan();

            var list = new List<KeyShare>();
            list.Add(new KeyShare()
            {
                Group = NamedGroup.ffdhe2048,
                KeyExchange = (ServerConnectionId.Generate().ConnectionIdBytes)
            });
            list.Add(new KeyShare()
            {
                Group = NamedGroup.secp521r1,
                KeyExchange = (ServerConnectionId.Generate().ConnectionIdBytes)
            });

            foreach (var actual in list)
            {
                var afterWrite = span.Write(actual);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(out KeyShare result);

                Assert.AreEqual(actual, result);
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
            }

            {
                List<KeyShare> result = new List<KeyShare>();

                var afterWrite = span.Write(list);
                var afterRead = ((ReadOnlySpan<byte>)span).Read(result);

                Assert.IsTrue(list.SequenceEqual(result));
                Assert.IsTrue(afterWrite.SequenceEqual(afterRead));
                Assert.AreEqual(2 + 2 * list.Count + 2 * list.Count + list.Sum(k => k.KeyExchange.Length), buffer.Length - afterWrite.Length);
            }
        }
    }
}

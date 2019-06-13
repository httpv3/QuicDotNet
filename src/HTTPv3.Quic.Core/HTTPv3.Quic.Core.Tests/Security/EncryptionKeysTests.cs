using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages;
using HTTPv3.Quic.Messages.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.Security
{
    [TestClass]
    public class EncryptionKeysTests
    {
        [TestMethod]
        public void HappyPathSet1()
        {
            var set = MessageSets.Set1;

            foreach (var file in set.Take(1))
            {
                var decConn = file.FromClient ? set.ServerConnection : set.ClientConnection;
                var encConn = file.FromClient ? set.ClientConnection : set.ServerConnection;

                var expected = file.Data;

                var datagram = new InboundDatagram(expected);
                foreach (var packet in datagram.AsPackets())
                {
                    var decrypted = packet.AsDecryptedPacket(decConn.KeyManager);

                    encConn.ServerConnectionId = new ServerConnectionId(decrypted.EncryptedPacket.DestId.ToArray());

                    var outbound = new OutboundInitialPacket(encConn, decrypted.EncryptedPacket.PacketNum, decrypted.Payload);

                    var buffer = new byte[1500];
                    var span = buffer.AsSpan();
                    var left = outbound.Write(span, encConn.KeyManager.Initial);
                    var actual = span.Subtract(left).ToArray();

                    Assert.IsTrue(expected.SequenceEqual(actual));
                }
            }
        }
    }
}

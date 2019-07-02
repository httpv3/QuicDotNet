using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages;
using HTTPv3.Quic.Messages.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
            var sequencesToSkip = new[] { 10, 12, 15, 17, 18 };
            var set = MessageSets.Set1;

            HappyPathTester(set, set.Where(f => !sequencesToSkip.Contains(f.Sequence)));
        }

        [TestMethod]
        public void HappyPathSet2()
        {
            var sequencesToSkip = new int[] { 5, 7, 10, 12, 13, 14 };
            var set = MessageSets.Set2;

            HappyPathTester(set, set.Where(f => !sequencesToSkip.Contains(f.Sequence)));
        }

        private void HappyPathTester(MessageSets set, IEnumerable<DataFile> files)
        {
            bool first = true;

            foreach (var file in files)
            {
                var decConn = file.FromClient ? set.ServerConnection : set.ClientConnection;
                var encConn = file.FromClient ? set.ClientConnection : set.ServerConnection;

                ConnectionId.DefaultLength = decConn.MyConnectionId.ConnectionIdBytes.Length;

                var expected = file.Data;
                var actual = new byte[expected.Length];
                var curSpan = actual.AsSpan();

                var datagram = new InboundDatagram(expected);
                foreach (var packet in datagram.AsPackets())
                {
                    var decrypted = packet.AsDecryptedPacket(decConn.KeyManager);

                    ServerConnectionId savedConnId = null;
                    if (first)
                    {
                        savedConnId = set.ClientConnection.ServerConnectionId;
                        set.ClientConnection.ServerConnectionId = new ServerConnectionId(decrypted.EncryptedPacket.DestId.ToArray());
                    }

                    var packetActual = WriteOutboundPacket(encConn, decrypted);
                    curSpan = curSpan.Write(packetActual);

                    if (first)
                    {
                        set.ClientConnection.ServerConnectionId = savedConnId;
                        first = false;
                    }
                }

                Debug.WriteLine("expected=" + BitConverter.ToString(expected).Replace("-", " "));
                Debug.WriteLine("actual=" + BitConverter.ToString(actual).Replace("-", " "));
                Debug.WriteLine($"Sequence={file.Sequence}");

                Assert.IsTrue(expected.SequenceEqual(actual));
            }
        }

        private Span<byte> WriteOutboundPacket(Connection conn, InboundPacket decrypted)
        {
            if (decrypted.EncryptedPacket is InboundEncryptedInitialPacket)
            {
                var outbound = new OutboundInitialPacket(conn, decrypted.EncryptedPacket.PacketNum, decrypted.Payload);

                var buffer = new byte[1500];
                var span = buffer.AsSpan();
                var left = outbound.Write(span, conn.KeyManager.Initial);
                return span.Subtract(left);
            }

            if (decrypted.EncryptedPacket is InboundEncryptedHandshakePacket)
            {
                var outbound = new OutboundHandshakePacket(conn, decrypted.EncryptedPacket.PacketNum, decrypted.Payload);

                var buffer = new byte[1500];
                var span = buffer.AsSpan();
                var left = outbound.Write(span, conn.KeyManager.Handshake.Result);
                return span.Subtract(left);
            }

            if (decrypted.EncryptedPacket is InboundEncryptedShortPacket)
            {
                var outbound = new OutboundShortPacket(conn, decrypted.EncryptedPacket.PacketNum, decrypted.Payload);

                var buffer = new byte[1500];
                var span = buffer.AsSpan();
                var left = outbound.Write(span, conn.KeyManager.Application.Result);
                return span.Subtract(left);
            }

            throw new NotImplementedException();
        }
    }
}

using HTTPv3.Quic.Messages.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Client
{
    [TestClass]
    public class InitialTests
    {
        [TestMethod]
        public void HappyPathSet1()
        {
            var set = MessageSets.Set1;

            Connection conn = new Connection()
            {
                InitialKeys = set.ServerInitialKeys,
                ClientConnectionId = set.ClientId,
                ServerConnectionId = set.ServerId,
            };

            var file = set[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            var obj = packet.ReadNextFrame();

            file = set[5];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();

            conn.HandshakeKeys = set.ServerHandshakeKeys;
            conn.EncryptionState = TLS.EncryptionState.Handshake;

            file = set[6];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();
            obj = packet.ReadNextFrame();

            conn.ApplicationKeys = set.ServerApplicationKeys[0];
            conn.EncryptionState = TLS.EncryptionState.Application;

            file = set[7];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();

            file = set[10];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();

            file = set[11];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();
            obj = packet.ReadNextFrame();
        }

    }
}

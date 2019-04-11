using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Server
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
                InitialKeys = set.ClientInitialKeys
            };

            var file = set[2];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            var obj = packet.ReadNextFrame();
            obj = packet.ReadNextFrame();

            conn.HandshakeKeys = set.ClientHandshakeKeys;
            conn.EncryptionState = TLS.EncryptionState.Handshake;

            file = set[3];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            obj = packet.ReadNextFrame();
            //obj = packet.ReadNextFrame();

        }

    }
}

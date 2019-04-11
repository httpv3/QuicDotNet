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
            var file = set[2];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, set.ClientConnection);
            var obj = packet.ReadNextFrame();
            obj = packet.ReadNextFrame();

            set.ClientConnection.HandshakeKeys = new TLS.HandshakeKeys("228c5bb650564b55f1bd36310694ffcae18690b381eec01715596ca4b217d403eb2beade40532ceae4f39d800222efac".ToByteArrayFromHex(), "2dae23de06bb5f69a76efe0f0a49899e072d0730a0a1cd5b5e5be52b951440fabca84e59f8926e340477b1a29a88d9c8".ToByteArrayFromHex(), CipherSuite.TLS_AES_256_GCM_SHA384, false);
            set.ClientConnection.EncryptionState = TLS.EncryptionState.Handshake;

            file = set[3];
            packet = Packet.ParseNewPacket(file.Data, file.FromClient, set.ClientConnection);
            //var obj = packet.ReadNextFrame();
            //obj = packet.ReadNextFrame();

        }

    }
}

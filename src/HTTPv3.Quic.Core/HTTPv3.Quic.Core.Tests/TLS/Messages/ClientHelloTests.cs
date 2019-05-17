using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    [TestClass]
    public class ClientHelloTests
    {
        [TestMethod]
        public void ProduceSet1_1()
        {
            //var set = HTTPv3.Quic.Messages.MessageSets.Set1;
            //var file = set[1];
            //var conn = file.FromClient ? set.ServerConnection : set.ClientConnection;
            //var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            //var c = packet.ReadNextFrame() as CryptoFrame;
            //var hello = c.HandshakeMessages[0] as ClientHello;

            //var data = new byte[2000];
            //var buffer = data.AsSpan();

            //buffer = hello.Write(buffer);
        }
    }
}

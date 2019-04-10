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
            var file = set[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, set.ServerConnection);
            var obj = packet.ReadNextFrame();
        }

    }
}

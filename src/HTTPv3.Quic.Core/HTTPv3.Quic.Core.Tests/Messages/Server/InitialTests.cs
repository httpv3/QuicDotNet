using HTTPv3.Quic.Messages.Common;
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
            var file = MessageSets.Set1[2];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient);
            //var obj = packet.ReadNextFrame();
        }

    }
}

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
                InitialKeys = set.ServerInitialKeys
            };

            var file = set[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
            var obj = packet.ReadNextFrame();
        }

    }
}

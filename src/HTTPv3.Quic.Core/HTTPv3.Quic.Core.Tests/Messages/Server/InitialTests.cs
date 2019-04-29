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

            foreach (var file in set)
            {
                var conn = file.FromClient ? set.ServerConnection : set.ClientConnection;
                var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
                packet.ReadAllFrames();
            }
        }

        //[TestMethod]
        //public void HappyPathSet2()
        //{
        //    var set = MessageSets.Set2;

        //    foreach (var file in set)
        //    {
        //        var conn = file.FromClient ? set.ServerConnection : set.ClientConnection;
        //        while (file.Data.Length > 0)
        //        {
        //            var packet = Packet.ParseNewPacket(file.Data, file.FromClient, conn);
        //            packet.ReadAllFrames();
        //            file.Data = packet.Bytes.ToArray();
        //        }
        //    }
        //}
    }
}

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
            var packet = MessageSets.Set1.Client_Initial;
            var header = new LongHeader(packet);

            var initial = new Initial(packet, header);
        }

    }
}

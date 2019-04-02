using HTTPv3.Quic.Messages.Client;
using HTTPv3.Quic.Messages.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    [TestClass]
    public class ClientInitialProtectionTests
    {
        //[TestMethod]
        //public void HappyTest()
        //{
        //    var unprotectedHeader = MessageSets.Set1.GetData("c.initial.unprotectedheader.bin");
        //    var unprotectedPayload = MessageSets.Set1.GetData("c.initial.unprotectedpayload.bin");
        //    var initialSecretExpected = MessageSets.Set1.GetData("c.initial.initialsecret.bin");
        //    var clientInitialSecretExpected = MessageSets.Set1.GetData("c.initial.clientinitialsecret.bin");
        //    var keyExpected = MessageSets.Set1.GetData("c.initial.key.bin");
        //    var ivExpected = MessageSets.Set1.GetData("c.initial.iv.bin");
        //    var hpExpected = MessageSets.Set1.GetData("c.initial.hp.bin");
        //    var finalPacket = MessageSets.Set1.GetData("c.initial.finalpacket.bin");

        //    var header = new LongHeader(unprotectedHeader);
        //    var init = new Initial(unprotectedHeader, header);
        //    var cip = new ClientInitialProtection(header, init.PacketNumber, unprotectedHeader);

        //    Assert.IsTrue(initialSecretExpected.SequenceEqual(cip.InitialSecret));
        //    Assert.IsTrue(clientInitialSecretExpected.SequenceEqual(cip.ClientInitialSecret));
        //    Assert.IsTrue(keyExpected.SequenceEqual(cip.Key));
        //    Assert.IsTrue(ivExpected.SequenceEqual(cip.IV));
        //    Assert.IsTrue(hpExpected.SequenceEqual(cip.HP));

        //    Assert.IsTrue(finalPacket.SequenceEqual(cip.ProtectFrame(unprotectedPayload)));
        //}

        //[TestMethod]
        //public void VerifyHardCodedValues()
        //{
        //    Assert.IsTrue(MessageSets.Set1.GetData("c.initial.initialsalt.bin").SequenceEqual(ClientInitialProtection.InitialSalt));
        //    Assert.IsTrue(MessageSets.Set1.GetData("c.initial.clientin.bin").SequenceEqual(ClientInitialProtection.ClientIn));
        //    Assert.IsTrue(MessageSets.Set1.GetData("c.initial.quickey.bin").SequenceEqual(ClientInitialProtection.QuicKey));
        //    Assert.IsTrue(MessageSets.Set1.GetData("c.initial.quiciv.bin").SequenceEqual(ClientInitialProtection.QuicIV));
        //    Assert.IsTrue(MessageSets.Set1.GetData("c.initial.quichp.bin").SequenceEqual(ClientInitialProtection.QuicHP));
        //}
    }
}

using HTTPv3.Quic.Exceptions.Parsing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    [TestClass]
    public class LongHeaderTests
    {
        [TestMethod]
        public void HappyPathSet1()
        {
            var packet = MessageSets.Set1.Client_Initial;

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = new ReadOnlySpan<byte>("d65881936984fbb3".ToByteArrayFromHex());
            var sourceConnId = new ReadOnlySpan<byte>("928f811fcf9b1d12".ToByteArrayFromHex());

            var header = new LongHeader(packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(0x9, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(22, header.Length);
        }

        [TestMethod]
        public void ThrowExceptionIfNotLongHeader()
        {
            var packet = MessageSets.Set1.Client_Initial;
            packet[0] ^= 0x80;

            Assert.ThrowsException<LongHeaderParsingException>(() => new LongHeader(packet));
        }

        [TestMethod]
        public void ThrowExceptionIfFixedBitIsZero()
        {
            var packet = MessageSets.Set1.Client_Initial;
            packet[0] ^= 0x40;

            Assert.ThrowsException<LongHeaderParsingException>(() => new LongHeader(packet));
        }

        [TestMethod]
        public void ThrowExceptionIfTooSmall()
        {
            var packet = MessageSets.Set1.Client_Initial;

            int wayTooSmall = 5;
            int tooSmallForIdLength = 21;
            int justRight = 22;

            Assert.ThrowsException<LongHeaderParsingException>(() => new LongHeader(new ReadOnlySpan<byte>(packet, 0, wayTooSmall)));

            Assert.ThrowsException<LongHeaderParsingException>(() => new LongHeader(new ReadOnlySpan<byte>(packet, 0, tooSmallForIdLength)));

            var good = new LongHeader(new ReadOnlySpan<byte>(packet, 0, justRight));
        }

        [TestMethod]
        public void TestParseConnIDLength()
        {
            Assert.AreEqual(0, LongHeader.ParseConnIDLength(0x0));
            Assert.AreEqual(4, LongHeader.ParseConnIDLength(0x1));
            Assert.AreEqual(8, LongHeader.ParseConnIDLength(0x5));
            Assert.AreEqual(18, LongHeader.ParseConnIDLength(0xF));
        }

        [TestMethod]
        public void TestParsePacketNumberLength()
        {
            Assert.AreEqual(1, LongHeader.ParsePacketNumberLength(new byte[] { 0x0 }));
            Assert.AreEqual(2, LongHeader.ParsePacketNumberLength(new byte[] { 0x1 }));
            Assert.AreEqual(3, LongHeader.ParsePacketNumberLength(new byte[] { 0x2 }));
            Assert.AreEqual(4, LongHeader.ParsePacketNumberLength(new byte[] { 0x3 }));
            Assert.AreEqual(1, LongHeader.ParsePacketNumberLength(new byte[] { 0xF0 }));
        }

        [TestMethod]
        public void TestParseVersionType()
        {
            Assert.AreEqual(VersionTypes.Draft_1, LongHeader.ParseVersionType("FF000001".ToByteArrayFromHex()));
            Assert.AreEqual(VersionTypes.Draft_18, LongHeader.ParseVersionType("FF000012".ToByteArrayFromHex()));
            Assert.AreEqual(VersionTypes.Draft_19, LongHeader.ParseVersionType("FF000013".ToByteArrayFromHex()));
            Assert.AreEqual(VersionTypes.UnknownDraft, LongHeader.ParseVersionType("FF000099".ToByteArrayFromHex()));
            Assert.AreEqual(VersionTypes.VersionNegotiation, LongHeader.ParseVersionType("0000.0000".ToByteArrayFromHex()));
            Assert.AreEqual(VersionTypes.Unknown, LongHeader.ParseVersionType("1234.5678".ToByteArrayFromHex()));
        }

        [TestMethod]
        public void NoDestinationConnId()
        {
            var packet = MessageSets.Set1.Client_Initial;

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = ReadOnlySpan<byte>.Empty;
            var sourceConnId = new ReadOnlySpan<byte>("d65881936984fbb3".ToByteArrayFromHex());

            packet[5] &= 0x0f; // Zero out the DCIL

            var header = new LongHeader(packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(0x9, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(14, header.Length);
        }

        [TestMethod]
        public void NoSourceConnId()
        {
            var packet = MessageSets.Set1.Client_Initial;

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = new ReadOnlySpan<byte>("d65881936984fbb3".ToByteArrayFromHex());
            var sourceConnId = ReadOnlySpan<byte>.Empty;

            packet[5] &= 0xf0; // Zero out the SCIL

            var header = new LongHeader(packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(0x9, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(14, header.Length);
        }
    }
}

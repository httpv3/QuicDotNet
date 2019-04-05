using HTTPv3.Quic.Exceptions.Parsing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace HTTPv3.Quic.Messages.Common
{
    [TestClass]
    public class LongHeaderTests
    {
        [TestMethod]
        public void HappyPathSet1()
        {
            var file = MessageSets.Set1[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient);

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = new ReadOnlySpan<byte>("174d1953def9d2c2".ToByteArrayFromHex());
            var sourceConnId = new ReadOnlySpan<byte>("2a854833d96efe9c".ToByteArrayFromHex());

            var header = new LongHeader(ref packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(null, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(22, header.HeaderBytes.Length);
        }

        [TestMethod]
        public void ThrowExceptionIfNotLongHeader()
        {
            var bytes = MessageSets.Set1[1].Data;
            bytes[0] ^= 0x80;

            Assert.ThrowsException<LongHeaderParsingException>(() => { var p = new Packet(bytes, true); new LongHeader(ref p); });
        }

        [TestMethod]
        public void ThrowExceptionIfFixedBitIsZero()
        {
            var bytes = MessageSets.Set1[1].Data;
            bytes[0] ^= 0x40;

            Assert.ThrowsException<LongHeaderParsingException>(() =>
            {
                var p = new Packet(bytes, true);
                new LongHeader(ref p);
            });
        }

        [TestMethod]
        public void ThrowExceptionIfTooSmall()
        {
            var bytes = MessageSets.Set1[1].Data;

            int wayTooSmall = 5;
            int tooSmallForIdLength = 21;
            int justRight = 22;

            Assert.ThrowsException<LongHeaderParsingException>(() => {
                var p = new Packet(new Span<byte>(bytes, 0, wayTooSmall), true);
                new LongHeader(ref p);
            });
            Assert.ThrowsException<LongHeaderParsingException>(() => {
                var p = new Packet(new Span<byte>(bytes, 0, tooSmallForIdLength), true);
                new LongHeader(ref p);
            });

            var goodP = new Packet(new Span<byte>(bytes, 0, justRight), true);
            var good = new LongHeader(ref goodP);
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
            var file = MessageSets.Set1[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient);

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = ReadOnlySpan<byte>.Empty;
            var sourceConnId = new ReadOnlySpan<byte>("174d1953def9d2c2".ToByteArrayFromHex());

            packet.Bytes[5] &= 0x0f; // Zero out the DCIL

            var header = new LongHeader(ref packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(null, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(14, header.HeaderBytes.Length);
        }

        [TestMethod]
        public void NoSourceConnId()
        {
            var file = MessageSets.Set1[1];
            var packet = Packet.ParseNewPacket(file.Data, file.FromClient);

            var version = new ReadOnlySpan<byte>("ff000012".ToByteArrayFromHex());
            var versionType = VersionTypes.Draft_18;
            var destConnId = new ReadOnlySpan<byte>("174d1953def9d2c2".ToByteArrayFromHex());
            var sourceConnId = ReadOnlySpan<byte>.Empty;

            packet.Bytes[5] &= 0xf0; // Zero out the SCIL

            var header = new LongHeader(ref packet);

            Assert.AreEqual(LongHeaderPacketTypes.Initial, header.LongPacketType);
            Assert.AreEqual(null, header.TypeSpecificBits);
            Assert.IsTrue(version.SequenceEqual(header.Version));
            Assert.AreEqual(versionType, header.VersionType);

            Assert.IsTrue(destConnId.SequenceEqual(header.DestinationConnID));
            Assert.IsTrue(sourceConnId.SequenceEqual(header.SourceConnID));

            Assert.AreEqual(14, header.HeaderBytes.Length);
        }
    }
}

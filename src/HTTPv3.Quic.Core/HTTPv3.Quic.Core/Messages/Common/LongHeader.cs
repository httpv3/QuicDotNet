using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Extensions;
using System;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("HTTPv3.Quic.Core.Tests")]
namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal ref struct LongHeader
    {
        public readonly ReadOnlySpan<byte> HeaderBytes;

        public readonly LongHeaderPacketTypes LongPacketType;
        public byte? TypeSpecificBits;

        public readonly ReadOnlySpan<byte> Version;
        public readonly VersionTypes VersionType;

        public readonly ReadOnlySpan<byte> DestinationConnID;

        public readonly ReadOnlySpan<byte> SourceConnID;


        public LongHeader(ref Packet packet)
        {
            if (packet.Bytes.Length < Header.StartOfConnIDs_Offset) throw new LongHeaderParsingException($"Minimum Size of Long Header is {Header.StartOfConnIDs_Offset} bytes long.");

            if ((packet.Bytes[Header.HeaderForm_Offset] & Header.HeaderForm_Mask) == 0) throw new LongHeaderParsingException("Error trying to parse non Long Header into Long Header.");

            if ((packet.Bytes[Header.FixedBit_Offset] & Header.FixedBit_Mask) == 0) throw new LongHeaderParsingException("Fixed bit is 0.");

            LongPacketType = (LongHeaderPacketTypes)((packet.Bytes[Header.LongPacketType_Offset] & Header.LongPacketType_Mask) >> Header.LongPacketType_Shift);
            TypeSpecificBits = null;

            Version = packet.Bytes.Slice(Header.Version_Offset, Header.Version_Length);
            VersionType = ParseVersionType(Version);

            int DCIL = ConnectionId.ParseLengthByte((byte)((packet.Bytes[Header.DCIL_Offset] & Header.DCIL_Mask) >> Header.DCIL_Shift));
            int SCIL = ConnectionId.ParseLengthByte((byte)(packet.Bytes[Header.SCIL_Offset] & Header.SCIL_Mask));

            int destionationConnIdOffset = Header.StartOfConnIDs_Offset; 
            int sourceConnIdOffset = destionationConnIdOffset + DCIL;
            var length = sourceConnIdOffset + SCIL;

            if (packet.Bytes.Length < length) throw new LongHeaderParsingException($"Computed Size of Long Header is {length} only {packet.Bytes.Length} bytes available.");

            HeaderBytes = packet.Bytes.Slice(0, length);

            DestinationConnID = DCIL == 0 ? ReadOnlySpan<byte>.Empty : packet.Bytes.Slice(destionationConnIdOffset, DCIL);
            SourceConnID = SCIL == 0 ? ReadOnlySpan<byte>.Empty : packet.Bytes.Slice(sourceConnIdOffset, SCIL);
        }

        internal void RemoveHeaderProtection(ref Packet p)
        {
            p.Bytes[0] ^= (byte)(p.HeaderProtectionMask[0] & 0xF);

            TypeSpecificBits = (byte)(HeaderBytes[Header.TypeSpecificBits_Offset] & Header.TypeSpecificBits_Mask);
        }

        public static VersionTypes ParseVersionType(ReadOnlySpan<byte> version)
        {
            var val = version.ToUInt32();
            if (Enum.IsDefined(typeof(VersionTypes), val))
                return (VersionTypes)Enum.ToObject(typeof(VersionTypes), val);

            if (version[0] == 0xFF)
                return VersionTypes.UnknownDraft;

            return VersionTypes.Unknown;
        }
    }

    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets - Table 5: Long Header Packet Types
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal enum LongHeaderPacketTypes : byte
    {
        Initial = 0x0,
        ZeroRTT = 0x1,
        Handshake = 0x2,
        Retry = 0x3,
    }

    // IETF quic-transport draft-19
    // 15.  Versions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-15
    internal enum VersionTypes : uint
    {
        Unknown = 0xFFFFFFFF,
        UnknownDraft = 0xFF000000,
        VersionNegotiation = 0x00000000,
        Version1 = 0x00000001,
        Draft_1 = 0xFF000001,
        Draft_2 = 0xFF000002,
        Draft_3 = 0xFF000003,
        Draft_4 = 0xFF000004,
        Draft_5 = 0xFF000005,
        Draft_6 = 0xFF000006,
        Draft_7 = 0xFF000007,
        Draft_8 = 0xFF000008,
        Draft_9 = 0xFF000009,
        Draft_10 = 0xFF00000A,
        Draft_11 = 0xFF00000B,
        Draft_12 = 0xFF00000C,
        Draft_13 = 0xFF00000D,
        Draft_14 = 0xFF00000E,
        Draft_15 = 0xFF00000F,
        Draft_16 = 0xFF000010,
        Draft_17 = 0xFF000011,
        Draft_18 = 0xFF000012,
        Draft_19 = 0xFF000013,
        Draft_20 = 0xFF000014,
    }
}

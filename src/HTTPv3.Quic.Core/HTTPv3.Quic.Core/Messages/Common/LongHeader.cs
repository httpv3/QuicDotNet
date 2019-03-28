using HTTPv3.Quic.Exceptions.Parsing;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

[assembly: InternalsVisibleTo("HTTPv3.Quic.Core.Tests")]
namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.2.  Long Header Packets
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.2
    internal readonly ref struct LongHeader
    {
        public readonly int Length;

        public readonly LongHeaderPacketTypes LongPacketType;
        public readonly byte TypeSpecificBits;

        public readonly ReadOnlySpan<byte> Version;
        public readonly VersionTypes VersionType;

        public readonly ReadOnlySpan<byte> DestinationConnID;

        public readonly ReadOnlySpan<byte> SourceConnID;


        public LongHeader(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < Header.StartOfConnIDsOffset) throw new LongHeaderParsingException($"Minimum Size of Long Header is {Header.StartOfConnIDsOffset} bytes long.");

            if ((packet[Header.HeaderFormOffset] & Header.HeaderFormMask) == 0) throw new LongHeaderParsingException("Error trying to parse non Long Header into Long Header.");

            if ((packet[Header.FixedBitOffset] & Header.FixedBitMask) == 0) throw new LongHeaderParsingException("Fixed bit is 0.");

            LongPacketType = (LongHeaderPacketTypes)((packet[Header.LongPacketTypeOffset] & Header.LongPacketTypeMask) >> Header.LongPacketTypeShift);
            TypeSpecificBits = (byte)(packet[Header.TypeSpecificBitsOffset] & Header.TypeSpecificBitsMask);

            Version = packet.Slice(Header.VersionOffset, Header.VersionLength);
            VersionType = ParseVersionType(Version);

            int DCIL = ParseConnIDLength((byte)((packet[Header.DCILOffset] & Header.DCILMask) >> Header.DCILShift));
            int SCIL = ParseConnIDLength((byte)((packet[Header.SCILOffset] & Header.SCILMask)));

            int destionationConnIdOffset = Header.StartOfConnIDsOffset;
            int sourceConnIdOffset = destionationConnIdOffset + DCIL;
            Length = sourceConnIdOffset + SCIL;

            if (packet.Length < Length) throw new LongHeaderParsingException($"Computed Size of Long Header is {Length} only {packet.Length} bytes available.");

            DestinationConnID = DCIL == 0 ? ReadOnlySpan<byte>.Empty : packet.Slice(destionationConnIdOffset, DCIL);
            SourceConnID = SCIL == 0 ? ReadOnlySpan<byte>.Empty : packet.Slice(sourceConnIdOffset, SCIL);
        }

        public static int ParseConnIDLength(byte field)
        {
            if (field == 0x0) return 0x0;

            return field + 3;
        }

        public static int ParsePacketNumberLength(ReadOnlySpan<byte> packet)
        {
            return (packet[Header.PacketNumberLengthOffset] & Header.PacketNumberLengthMask) +1;
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
    }
}

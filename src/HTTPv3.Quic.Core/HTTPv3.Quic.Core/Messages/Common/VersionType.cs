using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 15.  Versions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-15
    internal enum VersionType : uint
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

    internal static class VersionTypeExtensions
    {
        public const int Length_NumBytes = 4;

        public static ReadOnlyMemory<byte> Read(this in ReadOnlyMemory<byte> bytesIn, out VersionType scheme)
        {
            var ret = bytesIn.Read(Length_NumBytes, out uint val);

            scheme = ParseValue(val);

            return ret;
        }

        public static VersionType ParseValue(uint value)
        {
            if (Enum.IsDefined(typeof(VersionType), value))
                return (VersionType)value;

            if ((value & (uint)VersionType.UnknownDraft) == (uint)VersionType.UnknownDraft)
                return VersionType.UnknownDraft;

            return VersionType.Unknown;
        }

        public static Span<byte> Write(this in Span<byte> buffer, VersionType value)
        {
            return buffer.Write((uint)value, Length_NumBytes);
        }
    }
}

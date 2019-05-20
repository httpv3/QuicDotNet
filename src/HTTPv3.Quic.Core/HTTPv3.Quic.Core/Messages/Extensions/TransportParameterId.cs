using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.TLS.Messages;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace HTTPv3.Quic.Messages.Extensions
{
    // IETF quic-transport draft-19
    // 18.1.  Transport Parameter Definitions
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-18.1
    internal static class TransportParameterIdExtensions
    {
        public const int Type_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out TransportParameterId type)
        {
            var ret = bytesIn.Read(Type_NumBytes, out ushort val);

            type = ParseValue(val);

            return ret;
        }

        public static TransportParameterId ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(TransportParameterId), value))
                return (TransportParameterId)value;

            return TransportParameterId.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, TransportParameterId type)
        {
            return buffer.Write((ushort)type, Type_NumBytes);
        }

    }

    internal enum TransportParameterId : ushort
    {
        OriginalConnectionId = 0,
        IdleTimeout = 1,
        StatelessResetToken = 2,
        MaxPacketSize = 3,
        InitialMaxData = 4,
        InitialMaxStreamDataBidiLocal = 5,
        InitialMaxStreamDataBidiRemote = 6,
        InitialMaxStreamDataUni = 7,
        InitialMaxStreamsBidi = 8,
        InitialMaxStreamsUni = 9,
        AckDelayExponent = 10,
        MaxAckDelay = 11,
        DisableMigration = 12,
        PreferredAddress = 13,

        NA = 0xffff,
    }
}

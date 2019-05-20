using HTTPv3.Quic.Messages.Extensions;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal static class Extension
    {
        public const int Type_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out ExtensionType type)
        {
            var ret = bytesIn.Read(Type_NumBytes, out ushort val);

            type = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> ReadExtension(this in ReadOnlySpan<byte> bytesIn, out ExtensionType type, out ReadOnlySpan<byte> extBytes)
        {
            return bytesIn.Read(out type)
                          .ReadNextTLSVariableLength(Length_NumBytes, out extBytes);
        }

        public static ExtensionType ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(ExtensionType), value))
                return (ExtensionType)value;

            return ExtensionType.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, ExtensionType type)
        {
            return buffer.Write((ushort)type, Type_NumBytes);
        }

        public static Span<byte> WriteExtension(this in Span<byte> buffer, ExtensionType type, SpanAction<byte, VectorState> action)
        {
            return buffer.Write(type).WriteVector(Length_NumBytes, action);
        }
    }

    internal enum ExtensionType : ushort
    {
        ServerName = 0,
        MaxFragmentLength = 1,
        StatusRequest = 5,
        SupportedGroups = 10,
        SignatureAlgorithms = 13,
        UseSrtp = 14,
        Heartbeat = 15,
        ApplicationLayerProtocolNegotiation = 16,
        SignedCertificateTimestamp = 18,
        ClientCertificateType = 19,
        ServerCertificateType = 20,
        Padding = 21,
        PreSharedKey = 41,
        EarlyData = 42,
        SupportedVersions = 43,
        Cookie = 44,
        PskKeyExchangeModes = 45,
        CertificateAuthorities = 47,
        OidFilters = 48,
        PostHandshakeAuth = 49,
        SignatureAlgorithmsCert = 50,
        KeyShare = 51,
        QuicTransportParameters = 0xffa5,

        NA = 0xff,
    }
}

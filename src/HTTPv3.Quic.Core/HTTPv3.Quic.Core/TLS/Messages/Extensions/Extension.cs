using HTTPv3.Quic.Messages.Extensions;
using System;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal static class Extension
    {
        public const int Type_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ExtensionWriter AddExtension(this in Span<byte> buffer, ExtensionType type)
        {
            var lengthStart = buffer.Write(type);
            var start = lengthStart.Slice(Extension.Length_NumBytes);

            return new ExtensionWriter()
            {
                LengthStart = lengthStart,
                Start = start,
                Current = start
            };
        }

        public static ExtensionType ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(ExtensionType), value))
                return (ExtensionType)value;

            return ExtensionType.NA;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out ExtensionReader rdr)
        {
            rdr = new ExtensionReader();

            var ret = bytesIn.Read(out rdr.Type)
                       .ReadNextTLSVariableLength(Extension.Length_NumBytes, out rdr.Data);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out ExtensionType type)
        {
            var ret = bytesIn.Read(Extension.Type_NumBytes, out ushort val);

            type = ParseValue(val);

            return ret;
        }

        public static Span<byte> Write(this in Span<byte> buffer, ExtensionType cs)
        {
            return buffer.Write((ushort)cs, Extension.Type_NumBytes);
        }
    }

    internal ref struct ExtensionReader
    {
        public ExtensionType Type;
        public ReadOnlySpan<byte> Data;
    }

    internal ref struct ExtensionWriter
    {
        public Span<byte> LengthStart;
        public Span<byte> Start;
        public Span<byte> Current;

        public Span<byte> Close()
        {
            int len = Current.Length - Start.Length;
            LengthStart.Write(len, Extension.Length_NumBytes);

            return Current;
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

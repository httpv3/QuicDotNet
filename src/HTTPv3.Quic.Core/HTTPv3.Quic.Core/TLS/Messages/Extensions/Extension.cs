using HTTPv3.Quic.Messages.Extensions;
using System;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class Extension
    {
        public const int Type_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public ExtensionType ExtensionType;

        public Extension(ExtensionType extensionType)
        {
            ExtensionType = extensionType;
        }

        public static Extension ParseServerHello(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(Type_NumBytes, out uint typeInt)
                       .ReadNextTLSVariableLength(Length_NumBytes, out var extBytes);

            ExtensionType type = (ExtensionType)typeInt;

            switch (type)
            {
                case ExtensionType.ServerName:
                    return new ServerName(extBytes);
                case ExtensionType.SupportedVersions:
                    return new SupportedVersionsServerHello(extBytes);
                case ExtensionType.SupportedGroups:
                    return null; // new SupportedGroups(extBytes);
                case ExtensionType.SignatureAlgorithms:
                    return null; // SignatureAlgorithms(extBytes);
                case ExtensionType.KeyShare:
                    return null; // KeyShare.ParseOne(ref extBytes);
                case ExtensionType.PskKeyExchangeModes:
                    return null; // PskKeyExchangeModes.Parse(extBytes);
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    return null; // ApplicationLayerProtocolNegotiation.Parse(extBytes);
                case ExtensionType.QuicTransportParameters:
                    return TransportParameters.Parse(extBytes, HandshakeType.EncryptedExtensions);
                default:
                    return null;
            }
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
    }
}

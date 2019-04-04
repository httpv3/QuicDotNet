﻿using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class Extension
    {
        public const int TypeNumBytes = 2;
        public const int LengthNumBytes = 2;

        public ExtensionType ExtensionType;

        public Extension(ExtensionType extensionType)
        {
            ExtensionType = extensionType;
        }

        public static Extension Parse(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(TypeNumBytes, out uint typeInt)
                       .ReadNextTLSVariableLength(LengthNumBytes, out var extBytes);

            ExtensionType type = (ExtensionType)typeInt;

            switch (type)
            {
                case ExtensionType.ServerName:
                    return new ServerName(extBytes);
                case ExtensionType.SupportedVersions:
                    return new SupportedVersions(extBytes);
                case ExtensionType.SupportedGroups:
                    return new SupportedGroups(extBytes);
                case ExtensionType.SignatureAlgorithms:
                    return new SignatureAlgorithms(extBytes);
                case ExtensionType.KeyShare:
                    return new KeyShares(extBytes);
                case ExtensionType.PskKeyExchangeModes:
                    return new PskKeyExchangeModes(extBytes);
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    return new ApplicationLayerProtocolNegotiation(extBytes);
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

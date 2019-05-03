using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.2.  Client Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.2
    internal class ClientHello : Handshake
    {
        public const int ProtocolVersion_NumBytes = 2;
        public const int Random_NumBytes = 32;
        public const int LegacySessionIdLength_NumBytes = 1;
        public const int CipherSuitesLength_NumBytes = 2;
        public const int LegacyCompressionMethods_NumBytes = 2;
        public const int ExtensionsLength_NumBytes = 2;

        public uint ProtocolVersion;
        public byte[] Random;

        string ServerName;
        List<ProtocolVersion> SupportedVersions = new List<ProtocolVersion>();
        List<NamedGroup> SupportedGroups = new List<NamedGroup>();
        List<SignatureScheme> SignatureAlgorithms = new List<SignatureScheme>();
        KeyShareClientHello KeyShareClientHello;
        PskKeyExchangeModes PskKeyExchangeModes;
        ApplicationLayerProtocolNegotiation ApplicationLayerProtocolNegotiation;
        TransportParameters TransportParameters;

        public ClientHello() : base(HandshakeType.ClientHello)
        {

        }

        public static ClientHello Parse(ReadOnlySpan<byte> data)
        {
            ClientHello ret = new ClientHello();

            data = data.ReadNextNumber(ProtocolVersion_NumBytes, out ret.ProtocolVersion)
                       .ReadNextBytes(Random_NumBytes, out ret.Random)
                       .ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out var legacySessionId)
                       .ReadNextTLSVariableLength(CipherSuitesLength_NumBytes, out var cipherSuiteBytes)
                       .ReadNextBytes(LegacyCompressionMethods_NumBytes, out ReadOnlySpan<byte> legacyCompressionMethods)
                       .ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ret.ParseExtension(ref extensionBytes);
            }

            return ret;
        }

        private void ParseExtension(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextNumber(Extension.Type_NumBytes, out uint typeInt)
                       .ReadNextTLSVariableLength(Extension.Length_NumBytes, out var extBytes);

            ExtensionType type = (ExtensionType)typeInt;

            switch (type)
            {
                case ExtensionType.ServerName:
                    ServerName = ServerNameList.Parse(extBytes);
                    break;
                case ExtensionType.SupportedVersions:
                    SupportedVersions = Extensions.SupportedVersions.ParseClientHello(extBytes);
                    break;
                case ExtensionType.SupportedGroups:
                    SupportedGroups = Extensions.SupportedGroups.Parse(extBytes);
                    break;
                case ExtensionType.SignatureAlgorithms:
                    SignatureAlgorithms = Extensions.SignatureAlgorithms.Parse(extBytes);
                    break;
                case ExtensionType.KeyShare:
                    KeyShareClientHello = new KeyShareClientHello(extBytes);
                    break;
                case ExtensionType.PskKeyExchangeModes:
                    PskKeyExchangeModes = new PskKeyExchangeModes(extBytes);
                    break;
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    ApplicationLayerProtocolNegotiation = new ApplicationLayerProtocolNegotiation(extBytes);
                    break;
                case ExtensionType.QuicTransportParameters:
                    TransportParameters = TransportParameters.Parse(extBytes, HandshakeType.ClientHello);
                    break;
                default:
                    break;
            }
        }

        public void Write()
        {

        }
    }
}

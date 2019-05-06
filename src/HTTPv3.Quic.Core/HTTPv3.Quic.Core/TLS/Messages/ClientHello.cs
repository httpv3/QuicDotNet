using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Org.BouncyCastle.Security;
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

        private static SecureRandom prng = new SecureRandom();

        public byte[] Random;

        CipherSuites CipherSuites = new CipherSuites();
        string ServerName;
        List<ProtocolVersion> SupportedVersions = new List<ProtocolVersion>();
        SupportedGroups SupportedGroups = new SupportedGroups();
        List<SignatureScheme> SignatureAlgorithms = new List<SignatureScheme>();
        List<KeyShare> KeyShares;
        List<PskKeyExchangeMode> PskKeyExchangeModes;
        List<byte[]> ApplicationLayerProtocolNegotiation;
        TransportParameters TransportParameters;

        public ClientHello() : base(HandshakeType.ClientHello)
        {

        }

        public static ClientHello Parse(ReadOnlySpan<byte> data)
        {
            ClientHello ret = new ClientHello();

            data = data.ReadNextBytes(ProtocolVersion_NumBytes, out ReadOnlySpan<byte> protocolVersion)
                       .ReadNextBytes(Random_NumBytes, out ret.Random)
                       .ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out var legacySessionId);

            data = ret.CipherSuites.Parse(data);

            data = data.ReadNextBytes(LegacyCompressionMethods_NumBytes, out ReadOnlySpan<byte> legacyCompressionMethods)
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
                    SupportedGroups.Parse(extBytes);
                    break;
                case ExtensionType.SignatureAlgorithms:
                    SignatureAlgorithms = Extensions.SignatureAlgorithms.Parse(extBytes);
                    break;
                case ExtensionType.KeyShare:
                    KeyShares = KeyShare.ParseArray(extBytes);
                    break;
                case ExtensionType.PskKeyExchangeModes:
                    PskKeyExchangeModes = Extensions.PskKeyExchangeModes.Parse(extBytes);
                    break;
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    ApplicationLayerProtocolNegotiation = Extensions.ApplicationLayerProtocolNegotiation.Parse(extBytes);
                    break;
                case ExtensionType.QuicTransportParameters:
                    TransportParameters = TransportParameters.Parse(extBytes, HandshakeType.ClientHello);
                    break;
                default:
                    break;
            }
        }

        public Span<byte> Write(Span<byte> data)
        {
            data = data.Write((ushort)ProtocolVersion.TLSv1_2)     // legacy_version 
                       .Write(SecureRandom.GetNextBytes(prng, 32)) // random
                       .WriteTLSVariableLength(LegacySessionIdLength_NumBytes, SecureRandom.GetNextBytes(prng, 32)); // legacy_session_id

            data = CipherSuites.Write(data)                        // cipher_suites
                        .Write(0x0);                               // legacy_compression_methods

            var extLengthLoc = data;
            var startOfExt = data = data.Slice(ExtensionsLength_NumBytes);

            //if (!string.IsNullOrWhiteSpace(ServerName))
            //    data = WriteExtension(data);

            var extLength = startOfExt.Length - data.Length;
            extLengthLoc.Write((ulong)extLength, ExtensionsLength_NumBytes);

            return data;
        }

        private Span<byte> WriteExtension(Span<byte> data)
        {
            throw new NotImplementedException();
        }
    }
}

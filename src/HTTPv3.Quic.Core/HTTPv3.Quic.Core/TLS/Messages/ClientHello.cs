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
        public const int Random_NumBytes = 32;
        public const int LegacySessionIdLength_NumBytes = 1;
        public const int LegacyCompressionMethods_NumBytes = 2;
        public const int ExtensionsLength_NumBytes = 2;

        private static SecureRandom prng = new SecureRandom();

        public byte[] Random;

        ProtocolVersion LegacyVersion;
        List<CipherSuite> CipherSuites = new List<CipherSuite>();
        string ServerName;
        SupportedVersionsRequest SupportedVersions = new SupportedVersionsRequest();
        SupportedGroupsRequest SupportedGroups = new SupportedGroupsRequest();
        SignatureAlgorithms SignatureAlgorithms = new SignatureAlgorithms();
        List<KeyShare> KeyShares = new List<KeyShare>();
        List<PskKeyExchangeMode> PskKeyExchangeModes;
        List<byte[]> ApplicationLayerProtocolNegotiation;
        TransportParameters TransportParameters;

        public ClientHello() : base(HandshakeType.ClientHello)
        {

        }

        public static ClientHello Parse(ReadOnlySpan<byte> data)
        {
            ClientHello ret = new ClientHello();

            data = data.Read(out ret.LegacyVersion)
                       .Read(Random_NumBytes, out ret.Random)
                       .ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out var legacySessionId)
                       .Read(ret.CipherSuites);

            data = data.Read(LegacyCompressionMethods_NumBytes, out ReadOnlySpan<byte> legacyCompressionMethods)
                       .ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ret.ParseExtension(ref extensionBytes);
            }

            return ret;
        }

        private void ParseExtension(ref ReadOnlySpan<byte> data)
        {
            data = data.Read(out ExtensionReader rdr);

            switch (rdr.Type)
            {
                case ExtensionType.ServerName:
                    ServerName = ServerNameList.Parse(rdr.Data);
                    break;
                case ExtensionType.SupportedVersions:
                    SupportedVersions.Parse(rdr.Data);
                    break;
                case ExtensionType.SupportedGroups:
                    SupportedGroups.Parse(rdr.Data);
                    break;
                case ExtensionType.SignatureAlgorithms:
                    SignatureAlgorithms.Parse(rdr.Data);
                    break;
                case ExtensionType.KeyShare:
                    rdr.Data.Read(KeyShares);
                    break;
                case ExtensionType.PskKeyExchangeModes:
                    PskKeyExchangeModes = Extensions.PskKeyExchangeModes.Parse(rdr.Data);
                    break;
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    ApplicationLayerProtocolNegotiation = Extensions.ApplicationLayerProtocolNegotiation.Parse(rdr.Data);
                    break;
                case ExtensionType.QuicTransportParameters:
                    TransportParameters = TransportParameters.Parse(rdr.Data, HandshakeType.ClientHello);
                    break;
                default:
                    break;
            }
        }

        public Span<byte> Write(Span<byte> data)
        {
            data = data.Write(ProtocolVersion.TLSv1_2)             // legacy_version 
                       .Write(SecureRandom.GetNextBytes(prng, 32)) // random
                       .WriteTLSVariableLength(LegacySessionIdLength_NumBytes, SecureRandom.GetNextBytes(prng, 32)) // legacy_session_id
                       .Write(CipherSuites)                        // cipher_suites
                       .Write(0x0);                               // legacy_compression_methods

            var extLengthLoc = data;
            var startOfExt = data = data.Slice(ExtensionsLength_NumBytes);

            if (KeyShares.Count > 0)
            {
                var ext = data.AddExtension(ExtensionType.KeyShare);
                ext.Current = ext.Current.Write(KeyShares);
                data = ext.Close();
            }

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

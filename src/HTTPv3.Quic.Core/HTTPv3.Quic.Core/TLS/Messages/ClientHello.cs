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
        public const int LegacySessionId_NumBytes = 32;
        public const int LegacySessionIdLength_NumBytes = 1;
        public const int LegacyCompressionMethods_NumBytes = 2;
        public const int ExtensionsLength_NumBytes = 2;

        private static SecureRandom prng = new SecureRandom();

        public byte[] Random = null;
        public byte[] LegacySessionId = null;

        ProtocolVersion LegacyVersion = ProtocolVersion.NA;
        List<CipherSuite> CipherSuites = new List<CipherSuite>();
        string ServerName = null;
        List<ProtocolVersion> SupportedVersions = new List<ProtocolVersion>();
        List<NamedGroup> SupportedGroups = new List<NamedGroup>();
        List<SignatureScheme> SignatureAlgorithms = new List<SignatureScheme>();
        List<KeyShare> KeyShares = new List<KeyShare>();
        List<PskKeyExchangeMode> PskKeyExchangeModes = new List<PskKeyExchangeMode>();
        List<string> ALPN = new List<string>();
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

            ret.LegacySessionId = legacySessionId.ToArray();

            data = data.Read(LegacyCompressionMethods_NumBytes, out ReadOnlySpan<byte> _)
                       .ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ret.ParseExtension(ref extensionBytes);
            }

            return ret;
        }

        private void ParseExtension(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadExtension(out var type, out var extBytes);

            switch (type)
            {
                case ExtensionType.ServerName:
                    extBytes.ReadServerNameVector(out ServerName);
                    break;
                case ExtensionType.SupportedVersions:
                    extBytes.Read(SupportedVersions);
                    break;
                case ExtensionType.SupportedGroups:
                    extBytes.Read(SupportedGroups);
                    break;
                case ExtensionType.SignatureAlgorithms:
                    extBytes.Read(SignatureAlgorithms);
                    break;
                case ExtensionType.KeyShare:
                    extBytes.Read(KeyShares);
                    break;
                case ExtensionType.PskKeyExchangeModes:
                    extBytes.Read(PskKeyExchangeModes);
                    break;
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    extBytes.ReadALPN(ALPN);
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
            if (Random == null || Random.Length != Random_NumBytes)
                Random = SecureRandom.GetNextBytes(prng, Random_NumBytes);
            if (LegacySessionId == null || LegacySessionId.Length != Random_NumBytes)
                LegacySessionId = SecureRandom.GetNextBytes(prng, LegacySessionId_NumBytes);

            data = data.Write(ProtocolVersion.TLSv1_2)             // legacy_version 
                       .Write(Random)                              // random
                       .WriteTLSVariableLength(LegacySessionIdLength_NumBytes, LegacySessionId) // legacy_session_id
                       .Write(CipherSuites)                        // cipher_suites
                       .Write(0x0);                                // legacy_compression_methods

            var extLengthLoc = data;
            var startOfExt = data = data.Slice(ExtensionsLength_NumBytes);

            if (KeyShares.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.KeyShare, (buf, state) =>
                {
                    buf.Write(KeyShares);
                    state.EndLength = buf.Length;
                });
            }

            if (!string.IsNullOrWhiteSpace(ServerName))
            {
                data = data.WriteExtension(ExtensionType.ServerName, (buf, state) =>
                {
                    buf.WriteServerNameVector(ServerName);
                    state.EndLength = buf.Length;
                });
            }

            if (ALPN.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.ApplicationLayerProtocolNegotiation, (buf, state) =>
                {
                    buf.WriteALPNVector(ALPN);
                    state.EndLength = buf.Length;
                });
            }

            if (SupportedVersions.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SupportedVersions, (buf, state) =>
                {
                    buf.Write(SupportedVersions);
                    state.EndLength = buf.Length;
                });
            }

            if (SignatureAlgorithms.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SignatureAlgorithms, (buf, state) =>
                {
                    buf.Write(SignatureAlgorithms);
                    state.EndLength = buf.Length;
                });
            }

            if (SupportedGroups.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SupportedGroups, (buf, state) =>
                {
                    buf.Write(SupportedGroups);
                    state.EndLength = buf.Length;
                });
            }

            //if (TransportParameters != null)
            //{
            //    data = data.WriteExtension(ExtensionType.QuicTransportParameters, (buf, state) =>
            //    {
            //        buf = TransportParameters.Write(buf);
            //        state.EndLength = buf.Length;
            //    });
            //}

            if (PskKeyExchangeModes.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.PskKeyExchangeModes, (buf, state) =>
                {
                    buf.Write(PskKeyExchangeModes);
                    state.EndLength = buf.Length;
                });
            }

            return data;
        }
    }
}

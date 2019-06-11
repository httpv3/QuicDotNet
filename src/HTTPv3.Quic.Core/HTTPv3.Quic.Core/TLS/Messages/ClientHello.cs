﻿using HTTPv3.Quic.Messages.Extensions;
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

        public ProtocolVersion LegacyVersion = ProtocolVersion.NA;
        public List<CipherSuite> CipherSuites = new List<CipherSuite>();
        public string ServerName = null;
        public List<ProtocolVersion> SupportedVersions = new List<ProtocolVersion>();
        public List<NamedGroup> SupportedGroups = new List<NamedGroup>();
        public List<SignatureScheme> SignatureAlgorithms = new List<SignatureScheme>();
        public List<KeyShare> KeyShares = new List<KeyShare>();
        public List<PskKeyExchangeMode> PskKeyExchangeModes = new List<PskKeyExchangeMode>();
        public List<string> ALPN = new List<string>();
        public List<UnknownExtension> UnknownExtensions = new List<UnknownExtension>();

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
                default:
                    extBytes = extBytes.ReadNextTLSVariableLength(UnknownExtension.ArrayLength_NumBytes, out var bytes);

                    UnknownExtensions.Add(new UnknownExtension()
                    {
                        ExtensionType = (ushort)type,
                        Bytes = bytes.ToArray(),
                    });

                    break;
            }
        }

        public Span<byte> Write(in Span<byte> buffer)
        {
            if (Random == null || Random.Length != Random_NumBytes)
                Random = SecureRandom.GetNextBytes(prng, Random_NumBytes);
            if (LegacySessionId == null || LegacySessionId.Length != Random_NumBytes)
                LegacySessionId = SecureRandom.GetNextBytes(prng, LegacySessionId_NumBytes);

            return buffer.Write((byte)HandshakeType.ClientHello)
                         .WriteVector(Handshake.Length_NumBytes, (buf, state) =>
                         {
                             buf = buf.Write(ProtocolVersion.TLSv1_2)                                          // legacy_version 
                                      .Write(Random)                                                           // random
                                      .WriteTLSVariableLength(LegacySessionIdLength_NumBytes, LegacySessionId) // legacy_session_id
                                      .Write(CipherSuites)                                                     // cipher_suites
                                      .Write(0x1).Write(0x0)                                                   // legacy_compression_methods
                                      .WriteVector(ExtensionsLength_NumBytes, (buf2, state2) =>
                                      {
                                          buf2 = WriteExtensions(buf2);
                                          state2.EndLength = buf2.Length;
                                      });
                             state.EndLength = buf.Length;
                         });
        }

        public Span<byte> WriteExtensions(in Span<byte> buffer)
        {
            var data = buffer;
            if (KeyShares.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.KeyShare, (buf, state) =>
                {
                    buf = buf.Write(KeyShares);
                    state.EndLength = buf.Length;
                });
            }

            if (!string.IsNullOrWhiteSpace(ServerName))
            {
                data = data.WriteExtension(ExtensionType.ServerName, (buf, state) =>
                {
                    buf = buf.WriteServerNameVector(ServerName);
                    state.EndLength = buf.Length;
                });
            }

            if (ALPN.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.ApplicationLayerProtocolNegotiation, (buf, state) =>
                {
                    buf = buf.WriteALPNVector(ALPN);
                    state.EndLength = buf.Length;
                });
            }

            if (SupportedVersions.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SupportedVersions, (buf, state) =>
                {
                    buf = buf.Write(SupportedVersions);
                    state.EndLength = buf.Length;
                });
            }

            if (SignatureAlgorithms.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SignatureAlgorithms, (buf, state) =>
                {
                    buf = buf.Write(SignatureAlgorithms);
                    state.EndLength = buf.Length;
                });
            }

            if (SupportedGroups.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.SupportedGroups, (buf, state) =>
                {
                    buf = buf.Write(SupportedGroups);
                    state.EndLength = buf.Length;
                });
            }

            if (PskKeyExchangeModes.Count > 0)
            {
                data = data.WriteExtension(ExtensionType.PskKeyExchangeModes, (buf, state) =>
                {
                    buf = buf.Write(PskKeyExchangeModes);
                    state.EndLength = buf.Length;
                });
            }

            foreach (var ext in UnknownExtensions)
                data = data.WriteExtension(ext.ExtensionType, (buf, state) =>
                {
                    buf = buf.Write(ext.Bytes);
                    state.EndLength = buf.Length;
                });

            return data;
        }
    }
}
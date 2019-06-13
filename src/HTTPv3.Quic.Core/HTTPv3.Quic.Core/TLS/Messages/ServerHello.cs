using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.3.  Server Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.3
    internal class ServerHello : Handshake
    {
        public const int ProtocolVersion_NumBytes = 2;
        public const int Random_NumBytes = 32;
        public const int LegacySessionIdLength_NumBytes = 1;
        public const int CipherSuite_NumBytes = 2;
        public const int LegacyCompressionMethod_NumBytes = 1;
        public const int ExtensionsLength_NumBytes = 2;

        public ProtocolVersion ProtocolVersion;
        public byte[] Random;
        public byte[] LegacySessionId;
        public CipherSuite CipherSuite;

        public KeyShare KeyShare;
        public ProtocolVersion SupportedVersion;
        public List<UnknownExtension> UnknownExtensions = new List<UnknownExtension>();

        public ServerHello() : base(HandshakeType.ServerHello)
        {
        }

        public static ServerHello Parse(ReadOnlySpan<byte> data)
        {
            ServerHello ret = new ServerHello();

            data = data.Read(out ret.ProtocolVersion)
                       .Read(Random_NumBytes, out ret.Random)
                       .ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out ret.LegacySessionId)
                       .Read(out ret.CipherSuite)
                       .Read(LegacyCompressionMethod_NumBytes, out ReadOnlySpan<byte> _)
                       .ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out ReadOnlySpan<byte> extensionBytes);

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
                case ExtensionType.SupportedVersions:
                    extBytes.Read(out SupportedVersion);
                    break;
                case ExtensionType.KeyShare:
                    extBytes.Read(out KeyShare);
                    break;
                default:
                    extBytes = extBytes.ReadNextTLSVariableLength(UnknownExtension.ArrayLength_NumBytes, out byte[] bytes);

                    UnknownExtensions.Add(new UnknownExtension()
                    {
                        ExtensionType = (ushort)type,
                        Bytes = bytes,
                    });

                    break;
            }
        }

    }
}

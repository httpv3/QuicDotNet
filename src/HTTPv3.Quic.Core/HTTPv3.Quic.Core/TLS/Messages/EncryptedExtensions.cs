using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    // The Transport Layer Security (TLS) Protocol Version 1.3
    // 4.1.3.  Server Hello
    // https://tools.ietf.org/html/rfc8446#section-4.1.3
    internal class EncryptedExtensions : Handshake
    {
        public const int ProtocolVersion_NumBytes = 2;
        public const int Random_NumBytes = 32;
        public const int LegacySessionIdLength_NumBytes = 1;
        public const int CipherSuite_NumBytes = 2;
        public const int LegacyCompressionMethod_NumBytes = 1;
        public const int ExtensionsLength_NumBytes = 2;

        public uint ProtocolVersion;
        public byte[] Random;

        public EncryptedExtensions(ReadOnlySpan<byte> data) : base(HandshakeType.EncryptedExtensions)
        {
            data = data.ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out ReadOnlySpan<byte> extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                extensionBytes = extensionBytes.Read(out ExtensionType type)
                                               .ReadNextTLSVariableLength(Extension.Length_NumBytes, out ReadOnlySpan<byte> extBytes);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
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
        public List<Extensions.Extension> ExtensionList = new List<Extensions.Extension>();

        public ClientHello(ReadOnlySpan<byte> data) : base(HandshakeType.ClientHello)
        {
            data = data.ReadNextNumber(ProtocolVersion_NumBytes, out ProtocolVersion);
            data = data.ReadNextBytes(Random_NumBytes, out Random);
            data = data.ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out var legacySessionId);
            data = data.ReadNextTLSVariableLength(CipherSuitesLength_NumBytes, out var cipherSuiteBytes);
            data = data.ReadNextBytes(LegacyCompressionMethods_NumBytes, out ReadOnlySpan<byte> legacyCompressionMethods);
            data = data.ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ExtensionList.Add(Extensions.Extension.Parse(ref extensionBytes));
            }
        }
    }
}

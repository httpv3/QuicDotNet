using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    internal class ClientHello : Handshake
    {
        public const int ProtocolVersionNumBytes = 2;
        public const int RandomNumBytes = 32;
        public const int LegacySessionIdLengthNumBytes = 1;
        public const int CipherSuitesLengthNumBytes = 2;
        public const int LegacyCompressionMethodsNumBytes = 2;
        public const int ExtensionsLengthNumBytes = 2;
        public uint ProtocolVersion;
        public byte[] Random;
        public List<Extensions.Extension> ExtensionList = new List<Extensions.Extension>();

        public ClientHello(ReadOnlySpan<byte> data) : base(HandshakeType.ClientHello)
        {
            data = data.ReadNextNumber(ProtocolVersionNumBytes, out ProtocolVersion);
            data = data.ReadNextBytes(RandomNumBytes, out Random);
            data = data.ReadNextTLSVariableLength(LegacySessionIdLengthNumBytes, out var legacySessionId);
            data = data.ReadNextTLSVariableLength(CipherSuitesLengthNumBytes, out var cipherSuiteBytes);
            data = data.ReadNextBytes(LegacyCompressionMethodsNumBytes, out ReadOnlySpan<byte> legacyCompressionMethods);
            data = data.ReadNextTLSVariableLength(ExtensionsLengthNumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ExtensionList.Add(Extensions.Extension.Parse(ref extensionBytes));
            }
        }
    }
}

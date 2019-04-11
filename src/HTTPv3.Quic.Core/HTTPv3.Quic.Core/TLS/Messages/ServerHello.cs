﻿using System;
using System.Collections.Generic;
using System.Text;

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

        public uint ProtocolVersion;
        public byte[] Random;
        public List<Extensions.Extension> ExtensionList = new List<Extensions.Extension>();

        public ServerHello(ReadOnlySpan<byte> data) : base(HandshakeType.ServerHello)
        {
            data = data.ReadNextNumber(ProtocolVersion_NumBytes, out ProtocolVersion)
                       .ReadNextBytes(Random_NumBytes, out Random)
                       .ReadNextTLSVariableLength(LegacySessionIdLength_NumBytes, out var legacySessionId)
                       .ReadNextNumber(CipherSuite_NumBytes, out var cipherSuiteNum)
                       .ReadNextBytes(LegacyCompressionMethod_NumBytes, out ReadOnlySpan<byte> legacyCompressionMethod)
                       .ReadNextTLSVariableLength(ExtensionsLength_NumBytes, out var extensionBytes);

            while (!extensionBytes.IsEmpty)
            {
                ExtensionList.Add(Extensions.Extension.ParseServerHello(ref extensionBytes));
            }
        }
    }
}
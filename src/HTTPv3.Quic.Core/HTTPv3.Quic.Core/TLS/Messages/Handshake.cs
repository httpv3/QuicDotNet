using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    internal class Handshake
    {
        public const int Length_NumBytes = 3;

        public HandshakeType MessageType;

        public Handshake(HandshakeType messageType)
        {
            MessageType = messageType;
        }

        public static Handshake Parse(ref ReadOnlySpan<byte> data)
        {
            data = data.ReadNextByte(out byte typeByte)
                       .ReadNextTLSVariableLength(Length_NumBytes, out var extensionBytes);

            HandshakeType type = (HandshakeType)typeByte;

            switch (type)
            {
                case HandshakeType.ClientHello:
                    return ClientHello.Parse(extensionBytes);
                case HandshakeType.ServerHello:
                    return new ServerHello(extensionBytes);
                case HandshakeType.EncryptedExtensions:
                    return new EncryptedExtensions(extensionBytes);
                case HandshakeType.Certificate:
                    return new CertificateExtension(extensionBytes);
                case HandshakeType.CertificateVerify:
                    return new CertificateVerify(extensionBytes);
                case HandshakeType.Finished:
                    return new FinishedExtension(extensionBytes);
                default:
                    return null;
            }
        }
    }

    internal enum HandshakeType : byte
    {
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        EndOfEarlyData = 5,
        EncryptedExtensions = 8,
        Certificate = 11,
        CertificateRequest = 13,
        CertificateVerify = 15,
        Finished = 20,
        KeyUpdate = 24,
        MessageHash = 254,
      }
}

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

        public static Handshake Parse(ReadOnlySpan<byte> data)
        {
            data = data.ReadNextByte(out byte typeByte)
                       .ReadNextNumber(Length_NumBytes, out uint length);

            HandshakeType type = (HandshakeType)typeByte;

            switch (type)
            {
                case HandshakeType.ClientHello:
                    return new ClientHello(data);
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

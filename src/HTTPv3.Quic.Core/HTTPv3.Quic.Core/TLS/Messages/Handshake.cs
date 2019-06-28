using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages
{
    public class Handshake
    {
        public const int Length_NumBytes = 3;

        public HandshakeType MessageType;

        public Handshake(HandshakeType messageType)
        {
            MessageType = messageType;
        }

        public static Handshake Parse(in RawRecord r)
        {
            switch (r.HandshakeType)
            {
                case HandshakeType.ClientHello:
                    return ClientHello.Parse(r.Data);
                case HandshakeType.ServerHello:
                    return ServerHello.Parse(r.Data);
                case HandshakeType.EncryptedExtensions:
                    return new EncryptedExtensions(r.Data);
                case HandshakeType.Certificate:
                    return new CertificateExtension(r.Data);
                case HandshakeType.CertificateVerify:
                    return new CertificateVerify(r.Data);
                case HandshakeType.Finished:
                    return FinishedExtension.Parse(r.Data);
                default:
                    return null;
            }
        }
    }

    public enum HandshakeType : byte
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

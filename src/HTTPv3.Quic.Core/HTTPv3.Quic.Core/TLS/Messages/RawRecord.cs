using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading;

namespace HTTPv3.Quic.TLS.Messages
{
    public class RawRecord
    {
        public const int Length_NumBytes = 3;

        public HandshakeType HandshakeType;
        public byte[] Data;

        internal static async IAsyncEnumerable<RawRecord> ReadRecords(ClientConnection conn, PipeReader reader, [EnumeratorCancellation] CancellationToken cancel)
        {
            while (!cancel.IsCancellationRequested)
            {
                byte[] handshakeHeader = await reader.ReadBytes(4, cancel);
                if (cancel.IsCancellationRequested)
                    break;

                var handshakeType = (HandshakeType)handshakeHeader[0];
                handshakeHeader.AsSpan().Slice(1).ReadNumber(Length_NumBytes, out var len);

                var data = await reader.ReadBytes((int)len, cancel);

                SaveMessageBytes(conn, handshakeType, handshakeHeader, data);

                yield return new RawRecord()
                {
                    HandshakeType = handshakeType,
                    Data = data
                };
            }
        }

        private static void SaveMessageBytes(ClientConnection conn, HandshakeType type, in ReadOnlySpan<byte> header, in ReadOnlySpan<byte> data)
        {
            switch (type)
            {
                case HandshakeType.ClientHello:
                    conn.ClientHelloBytes = CreateMessageBytes(header, data);
                    break;
                case HandshakeType.ServerHello:
                    conn.ServerHelloBytes = CreateMessageBytes(header, data);
                    break;
                case HandshakeType.EncryptedExtensions:
                    conn.EncryptedExtensionsBytes = CreateMessageBytes(header, data);
                    break;
                case HandshakeType.Certificate:
                    conn.CertificateBytes = CreateMessageBytes(header, data);
                    break;
                case HandshakeType.CertificateVerify:
                    conn.CertificateVerifyBytes = CreateMessageBytes(header, data);
                    break;
                case HandshakeType.Finished:
                    conn.ServerFinishedBytes = CreateMessageBytes(header, data);
                    break;
            }
        }

        private static byte[] CreateMessageBytes(in ReadOnlySpan<byte> header, in ReadOnlySpan<byte> data)
        {
            var ret = new byte[header.Length + data.Length];
            ret.AsSpan().Write(header).Write(data);
            return ret;
        }
    }
}

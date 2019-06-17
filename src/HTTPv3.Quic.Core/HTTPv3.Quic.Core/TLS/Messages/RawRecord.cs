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

                conn.AddProcessedMessage(handshakeHeader);

                var handshakeType = (HandshakeType)handshakeHeader[0];
                handshakeHeader.AsSpan().Slice(1).ReadNumber(Length_NumBytes, out var len);

                var data = await reader.ReadBytes((int)len, cancel);
                conn.AddProcessedMessage(data);

                yield return new RawRecord()
                {
                    HandshakeType = handshakeType,
                    Data = data
                };
            }
        }
    }
}

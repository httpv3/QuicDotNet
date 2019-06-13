using HTTPv3.Quic.Extensions;
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

        public static async IAsyncEnumerable<RawRecord> ReadRecords(PipeReader reader, [EnumeratorCancellation] CancellationToken cancel)
        {
            while (!cancel.IsCancellationRequested)
            {
                var handshakeType = (HandshakeType)await reader.ReadByte(cancel);
                var data = await reader.ReadTLSData(Length_NumBytes, cancel);
                yield return new RawRecord()
                {
                    HandshakeType = handshakeType,
                    Data = data
                };
            }
        }
    }
}

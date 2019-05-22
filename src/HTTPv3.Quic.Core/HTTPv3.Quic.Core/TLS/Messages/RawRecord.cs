using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic.TLS.Messages
{
    class RawRecord
    {
        public const int Length_NumBytes = 3;

        public HandshakeType HandshakeType;
        public byte[] Data;

        public static async IAsyncEnumerable<RawRecord> ReadRecords(PipeReader reader, [EnumeratorCancellation] CancellationToken cancel)
        {
            while (!cancel.IsCancellationRequested)
            {
                yield return new RawRecord()
                {
                    HandshakeType = (HandshakeType)await reader.ReadByte(cancel),
                    Data = await reader.ReadTLSData(Length_NumBytes, cancel)
                };
            }
        }
    }
}

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Extensions
{
    public static class PipeExtensions
    {
        public static async Task<byte> ReadByte(this PipeReader reader,  CancellationToken cancel)
        {
            return (await reader.ReadBytes(1, cancel))[0];
        }

        public static async Task<byte[]> ReadBytes(this PipeReader reader, int numBytes, CancellationToken cancel)
        {
            while (true)
            {
                ReadResult result = await reader.ReadAsync(cancel);

                if (result.IsCanceled)
                    return new byte[numBytes];

                ReadOnlySequence<byte> buffer = result.Buffer;

                if (buffer.Length < numBytes)
                {
                    reader.AdvanceTo(buffer.Start, buffer.End);
                    continue;
                }

                var data = buffer.Slice(0, numBytes).ToArray();

                var next = buffer.GetPosition(numBytes);

                reader.AdvanceTo(next);

                return data;
            }
        }

        public static async Task<uint> ReadUInt32(this PipeReader reader, int numBytes, CancellationToken cancel)
        {
            return (await reader.ReadBytes(numBytes, cancel)).AsSpan().ToUInt32();
        }

        public static async Task<byte[]> ReadTLSData(this PipeReader reader, int lengthNumBytes, CancellationToken cancel)
        {
            int length = (int)(await reader.ReadUInt32(lengthNumBytes, cancel));
            return await reader.ReadBytes(length, cancel);
        }
    }
}

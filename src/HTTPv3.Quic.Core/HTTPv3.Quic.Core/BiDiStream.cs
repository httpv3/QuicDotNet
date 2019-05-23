using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class BiDiStream
    {
        private PipeReader Input;
        private PipeWriter Output;

        public async Task<byte> ReadByte(CancellationToken cancel)
        {
            return (await Input.ReadBytes(1, cancel))[0];
        }

        public async Task<byte[]> ReadBytes(int numBytes, CancellationToken cancel)
        {
            while (true)
            {
                ReadResult result = await Input.ReadAsync(cancel);

                if (result.IsCanceled)
                    return new byte[numBytes];

                ReadOnlySequence<byte> buffer = result.Buffer;

                if (buffer.Length < numBytes)
                {
                    Input.AdvanceTo(buffer.Start, buffer.End);
                    continue;
                }

                var data = buffer.Slice(0, numBytes);

                var next = buffer.GetPosition(numBytes);

                Input.AdvanceTo(next);

                return data.ToArray();
            }
        }

        public async Task<int> ReadInt(int numBytes, CancellationToken cancel)
        {
            return (await Input.ReadBytes(numBytes, cancel)).ToInt32();
        }


        public async Task<byte[]> ReadTLSData(int lengthNumBytes, CancellationToken cancel)
        {
            int length = await Input.ReadInt(lengthNumBytes, cancel);
            return await Input.ReadBytes(length, cancel);
        }

    }
}

using HTTPv3.Quic.Messages.Frames;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class AckStream : IFrameStreamer
    {
        private readonly CancellationToken cancel;

        private ulong fromAppOffset = 0;
        private ulong toAppOffset = 0;

        private AwaitableQueue<AckFrame> frames = new AwaitableQueue<AckFrame>();

        public AvailableFrameInfo AvailableInfo { get; }

        public AckStream(CancellationToken cancel)
        {
            this.cancel = cancel;
            AvailableInfo = new AvailableFrameInfo(this);
        }


        public async Task<AckFrame> GetFrame(int numDesiredBytes)
        {
            var res = await fromApp.Reader.ReadAsync(cancel);
            AvailableInfo.Reset();

            var len = Math.Min(res.Buffer.Length, numDesiredBytes);

            var data = res.Buffer.Slice(0, len).ToArray();

            var ret = new CryptoFrame(fromAppOffset, data);

            fromAppOffset += (ulong)len;

            return ret;
        }

        internal async Task NewPacketProcessed(ulong packetNumber, DateTime received)
        {
            var frame = new AckFrame()
            {
                LargestAcknowledged = packetNumber,
                Delay = (ulong)((DateTime.UtcNow - received).TotalMilliseconds * 1000)
            };

            frames.Add(frame);
        }

        public async IAsyncEnumerable<AvailableFrameInfo> WaitBytesAvailable()
        {
            await foreach(var item in frames)
            {
                SetAvailable(item);

                yield return AvailableInfo;
            }
        }

        internal void AddToFromAppOffset(int offset)
        {
            fromAppOffset += (uint)offset;
            AvailableInfo.Reset();
        }

        private void SetAvailable(AckFrame frame)
        {
            var avail = frame.GetSize();
            AvailableInfo.Set(avail, avail);
        }
    }
}

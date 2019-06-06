using HTTPv3.Quic.Messages.Frames;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class CryptoStream
    {
        private readonly CancellationToken cancel;
        private readonly Pipe fromApp = new Pipe();
        private readonly Pipe toApp = new Pipe();

        private ulong fromAppOffset = 0;
        private ulong toAppOffset = 0;

        private Dictionary<ulong, CryptoFrame> frames = new Dictionary<ulong, CryptoFrame>();

        public CryptoStream(CancellationToken cancel)
        {
            this.cancel = cancel;
        }

        public PipeReader Reader => toApp.Reader;
        public PipeWriter Output => fromApp.Writer;

        internal async Task AddFrame(CryptoFrame frame)
        {
            if (toAppOffset == frame.Offset)
            {
                await SendToApp(frame);
            }
            else
            {
                lock (frames)
                {
                    frames[frame.Offset] = frame;
                }
            }

            if (frames.Count > 0)
                await DrainQueue();
        }

        internal async IAsyncEnumerable<(CryptoStream, long)> GetNumBytesAvailable()
        {
            var res = await fromApp.Reader.ReadAsync(cancel);
            while (!res.IsCanceled)
            {
                yield return (this, res.Buffer.Length);

                res = await fromApp.Reader.ReadAsync(cancel);
            }
        }

        internal async Task<CryptoFrame> GetFrame(int numDesiredBytes)
        {
            var res = await fromApp.Reader.ReadAsync(cancel);

            var len = Math.Min(res.Buffer.Length, numDesiredBytes);

            var data = res.Buffer.Slice(0, len).ToArray();

            var ret = new CryptoFrame(fromAppOffset, data);

            fromAppOffset += (ulong)len;

            return ret;
        }

        internal void AddToFromAppOffset(int offset)
        {
            fromAppOffset += (uint)offset;
        }

        private async Task DrainQueue()
        {
            while (frames.Count > 0)
            {
                CryptoFrame frame;

                lock (frames)
                {
                    if (!frames.Remove(toAppOffset, out frame))
                        return;
                }

                await SendToApp(frame);
            }
        }

        private async Task SendToApp(CryptoFrame frame)
        {
            await toApp.Writer.WriteAsync(frame.Data, cancel);

            toAppOffset += (ulong)frame.Data.Length;
        }
    }
}

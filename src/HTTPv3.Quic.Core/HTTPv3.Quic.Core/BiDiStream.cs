﻿using HTTPv3.Quic.Messages.Frames;
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
        public readonly ulong StreamId;
        private readonly CancellationToken cancel;
        private readonly Pipe fromApp = new Pipe();
        private readonly Pipe toApp = new Pipe();

        private ulong fromAppOffset = 0;
        private ulong toAppOffset = 0;

        private Dictionary<ulong, StreamFrame> frames = new Dictionary<ulong, StreamFrame>();

        public BiDiStream(ulong streamId, CancellationToken cancel)
        {
            StreamId = streamId;
            this.cancel = cancel;
        }

        public PipeReader Reader => toApp.Reader;
        public PipeWriter Output => fromApp.Writer;

        internal async Task AddFrame(StreamFrame frame)
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

        internal async IAsyncEnumerable<long> GetNumBytesAvailable()
        {
            var res = await fromApp.Reader.ReadAsync(cancel);
            while (!(res.IsCanceled || (res.IsCompleted && res.Buffer.Length == 0)))
            {
                yield return res.Buffer.Length;

                res = await fromApp.Reader.ReadAsync(cancel);
            }
        }

        internal async Task<StreamFrame> GetFrame(int numDesiredBytes)
        {
            var res = await fromApp.Reader.ReadAsync(cancel);

            var len = Math.Min(res.Buffer.Length, numDesiredBytes);

            var data = res.Buffer.Slice(0, len).ToArray();

            bool last = false;
            if (res.IsCompleted && res.Buffer.Length == len)
                last = true;

            var ret = new StreamFrame(StreamId, fromAppOffset, data, last);

            fromAppOffset += (ulong)len;

            return ret;
        }

        private async Task DrainQueue()
        {
            while (frames.Count > 0)
            {
                StreamFrame frame;

                lock (frames)
                {
                    if (!frames.Remove(toAppOffset, out frame))
                        return;
                }

                await SendToApp(frame);
            }
        }

        private async Task SendToApp(StreamFrame frame)
        {
            await toApp.Writer.WriteAsync(frame.Data, cancel);

            if (frame.LastFrame)
                toApp.Writer.Complete();

            toAppOffset += (ulong)frame.Data.Length;
        }
    }
}

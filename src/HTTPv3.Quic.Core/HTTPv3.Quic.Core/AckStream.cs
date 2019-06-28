﻿using HTTPv3.Quic.Messages.Frames;
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
    internal class AckStream : IFrameStreamer
    {
        private readonly CancellationToken cancel;

        public AvailableFrameInfo AvailableInfo { get; }

        private AwaitableQueue<AckFrame> frames = new AwaitableQueue<AckFrame>();
        private AckFrame currentFrame = null;

        public AckStream(CancellationToken cancel)
        {
            this.cancel = cancel;
            AvailableInfo = new AvailableFrameInfo(this);
        }


        public Task<IFrame> GetFrame(int numDesiredBytes)
        {
            IFrame ret = currentFrame;

            currentFrame = null;
            AvailableInfo.Reset();

            return Task.FromResult(ret);
        }

        internal void NewPacketProcessed(ulong packetNumber, DateTime received)
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
            await foreach (var frame in frames)
            {
                currentFrame = frame;
                SetAvailable();

                while (!AvailableInfo.Empty)
                    yield return AvailableInfo;
            }
        }

        private void SetAvailable()
        {
            var avail = currentFrame.GetSize();
            AvailableInfo.Set(avail, avail);
        }
    }
}

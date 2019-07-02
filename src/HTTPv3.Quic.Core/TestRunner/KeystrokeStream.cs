using HTTPv3.Quic;
using HTTPv3.Quic.Messages.Frames;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TestRunner
{
    public class KeystrokeStream
    {
        private readonly CancellationToken cancel;

        public int AvailableInfo => frames.Backlog;

        private AwaitableQueue<KeystrokeData> frames;
        private KeystrokeData currentFrame = null;

        public KeystrokeStream(CancellationToken cancel = default)
        {
            this.cancel = cancel;
            frames = new AwaitableQueue<KeystrokeData>(cancel);
        }

        public Task<KeystrokeData> GetFrame()
        {
            KeystrokeData ret = currentFrame;

            currentFrame = null;

            return Task.FromResult(ret);
        }

        internal void NewPacketProcessed(string letter, int num)
        {
            var frame = new KeystrokeData()
            {
                Letter = letter,
                Number = num
            };

            frames.Add(frame);
        }

        public async IAsyncEnumerable<KeystrokeStream> WaitBytesAvailable()
        {
            await foreach (var frame in frames)
            {
                currentFrame = frame;
                yield return this;
            }
        }
    }

    public class KeystrokeData
    {
        public string Letter;
        public int Number;
    }
}

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
    public class BiDiStream
    {
        private Pipe fromApplication = new Pipe();
        private Pipe toApplication = new Pipe();

        private ulong fromAppOffset = 0;
        private ulong toAppOffset = 0;

        private Dictionary<ulong, StreamFrame> frames = new Dictionary<ulong, StreamFrame>();

        public BiDiStream()
        {

        }

        internal BiDiStream(ulong fromAppOffset, ulong toAppOffset)
        {
            this.fromAppOffset = fromAppOffset;
            this.toAppOffset = toAppOffset;
        }

        public PipeReader Reader => toApplication.Reader;
        public PipeWriter Output => fromApplication.Writer;

        //internal bool HasDataFromApp => fromApplication.Reader.

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
            await toApplication.Writer.WriteAsync(frame.Data);

            if (frame.LastFrame)
                toApplication.Writer.Complete();

            toAppOffset += (ulong)frame.Data.Length;
        }
    }
}

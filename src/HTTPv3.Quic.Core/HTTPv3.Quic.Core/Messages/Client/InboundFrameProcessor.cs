using HTTPv3.Quic.Messages.Frames;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class InboundFrameProcessor
    {
        Receiver receiver;

        public InboundFrameProcessor(Receiver receiver)
        {
            this.receiver = receiver;
        }

        public async Task StartProcessing()
        {
            await foreach (var frame in receiver.GetFrames())
                ProcessFrame(frame);
        }

        void ProcessFrame(IFrame frame)
        {

        }
    }
}

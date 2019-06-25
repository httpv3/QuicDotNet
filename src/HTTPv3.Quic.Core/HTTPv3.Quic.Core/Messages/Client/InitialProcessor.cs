using HTTPv3.Quic.Messages.Common;
using HTTPv3.Quic.Messages.Frames;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Client
{
    internal class InitialProcessor
    {
        Connection conn;

        public InitialProcessor(Connection conn)
        {
            this.conn = conn;
        }

        public async Task Process(InboundPacket packet)
        {
            foreach (var frame in packet.AsFrames())
                await Process(frame);
        }

        public async Task Process(IFrame frame)
        {
            if (frame is CryptoFrame)
            {
                await conn.InitialStream.AddFrame(frame as CryptoFrame);
                return;
            }
        }
    }
}

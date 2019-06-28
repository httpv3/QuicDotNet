using System.Collections.Generic;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Frames
{
    internal interface IFrameStreamer
    {
        AvailableFrameInfo AvailableInfo { get; }

        Task<IFrame> GetFrame(int numDesiredBytes);

        IAsyncEnumerable<AvailableFrameInfo> WaitBytesAvailable();
    }
}

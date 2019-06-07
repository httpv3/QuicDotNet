using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Messages.Frames
{
    public interface IFrameStreamer
    {
        AvailableFrameInfo AvailableInfo { get; }

        Task<CryptoFrame> GetFrame(int numDesiredBytes);

        IAsyncEnumerable<AvailableFrameInfo> WaitBytesAvailable();
    }
}

namespace HTTPv3.Quic.Messages.Frames
{
    public class AvailableFrameInfo
    {
        public IFrameStreamer Streamer { get; private set; }
        public bool Empty => MaxSize == 0;

        public ushort MinimumSize;
        public ushort MaxSize;

        public AvailableFrameInfo(IFrameStreamer streamer)
        {
            Streamer = streamer;
            Reset();
        }

        public void Reset()
        {
            MinimumSize = ushort.MaxValue;
            MaxSize = 0;
        }

        public void Set(ushort minimumSize, ushort maxSize)
        {
            MinimumSize = minimumSize;
            MaxSize = maxSize;
        }
    }
}

namespace HTTPv3.Quic.Messages.Frames
{
    public enum TransportErrorCodes : ushort
    {
        NoError = 0x0,
        InternalError = 0x1,
        ServerBusy = 0x2,
        FlowControl = 0x3,
        StreamLimit = 0x4,
        StreamState = 0x5,
        FinalSize = 0x6,
        FrameEncoding = 0x7,
        TransportParameter = 0x8,
        ProtocolViolation = 0xA,
        InvalidMigration = 0xC,
        CryptoError = 0x100,

        Unknown = 0xFFFF
    }
}

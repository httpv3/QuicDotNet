using HTTPv3.Quic.Messages.Client;
using HTTPv3.Quic.Messages.Frames;
using System;

namespace HTTPv3.Quic.Messages.Common
{
    internal ref struct Packet
    {
        public Span<byte> Bytes;
        public Span<byte> Payload;
        public ReadOnlySpan<byte> PayloadCursor;
        public bool IsServer;
        public PacketState State;
        public Connection Connection;

        public LongHeader LongHeader;
        public Initial Initial;
        public Handshake Handshake;

        public ShortHeader ShortHeader;

        public ReadOnlySpan<byte> HeaderProtectionMask;
        public Span<byte> HeaderBytes;
        public Span<byte> EncryptedPayload;

        public uint PacketNumber;

        public Packet(Span<byte> bytes, bool isServer)
        {
            Bytes = bytes;
            Payload = null;
            PayloadCursor = null;
            Connection = null;
            IsServer = isServer;
            LongHeader = default;
            Initial = default;
            Handshake = default;

            ShortHeader = default;

            State = PacketState.Encrypted;
            HeaderProtectionMask = null;
            HeaderBytes = null;
            EncryptedPayload = null;

            PacketNumber = 0;
        }

        public static Packet ParseNewPacket(Span<byte> bytes, bool isServer, Connection conn = null)
        {
            Packet p = new Packet(bytes, isServer);

            if (Header.IsLongHeader(ref p))
            {
                p.LongHeader = new LongHeader(ref p);

                if (conn != null)
                {
                    p.Connection = conn;
                }
                else
                {
                    if (isServer)
                        p.Connection = ConnectionManager.GetOrCreate(new ClientConnectionId(p.LongHeader.SourceConnID.ToArray()), new ServerConnectionId(p.LongHeader.DestinationConnID.ToArray()), isServer);
                    else
                        p.Connection = ConnectionManager.GetOrCreate(new ClientConnectionId(p.LongHeader.DestinationConnID.ToArray()), new ServerConnectionId(p.LongHeader.SourceConnID.ToArray()), isServer);
                }

                switch (p.LongHeader.LongPacketType)
                {
                    case LongHeaderPacketTypes.Initial:
                        p.Initial = new Initial(ref p);

                        p.HeaderProtectionMask = p.Initial.ComputeDecryptionHeaderProtectionMask(ref p);
                        p.LongHeader.RemoveHeaderProtection(ref p);
                        p.Initial.RemoveHeaderProtection(ref p);

                        p.DecryptPayLoad(p.Connection.InitialKeys.EncryptionKeys);
                        break;
                    case LongHeaderPacketTypes.Handshake:
                        p.Handshake = new Handshake(ref p);

                        p.HeaderProtectionMask = p.Handshake.ComputeDecryptionHeaderProtectionMask(ref p);
                        p.LongHeader.RemoveHeaderProtection(ref p);
                        p.Handshake.RemoveHeaderProtection(ref p);

                        p.DecryptPayLoad(p.Connection.HandshakeKeys.EncryptionKeys);
                        break;
                }
            }
            else
            {
                if (conn != null)
                {
                    p.Connection = conn;
                }
                p.ShortHeader = new ShortHeader(ref p);

                p.HeaderProtectionMask = p.ShortHeader.ComputeDecryptionHeaderProtectionMask(ref p);
                p.ShortHeader.RemoveHeaderProtection(ref p);

                p.DecryptPayLoad(p.Connection.ApplicationKeys.EncryptionKeys);
            }

            return p;
        }

        public void ReadAllFrames()
        {
            while(!PayloadCursor.IsEmpty)
            {
                var frame = ReadNextFrame();
            }
        }

        public object ReadNextFrame()
        {
            if (PayloadCursor == null || PayloadCursor.Length == 0)
                return null;

            PayloadCursor = PayloadCursor.ReadNextByte(out var frameByte);

            var frameType = FrameTypes.Parse(frameByte);

            switch (frameType)
            {
                case FrameType.Ack:
                    return new AckFrame(ref this);
                case FrameType.ConnectionCloseApplication:
                    return new ConnectionCloseAppFrame(ref this);
                case FrameType.ConnectionCloseQuic:
                    return new ConnectionCloseQuicFrame(ref this);
                case FrameType.Crypto:
                    return new CryptoFrame(ref this);
                case FrameType.NewConnectionId:
                    return new NewConnectionIdFrame(ref this);
                default:
                    return null;
            }
        }

        private void DecryptPayLoad(TLS.EncryptionKeys keys)
        {
            PayloadCursor = Payload = keys.DecryptPayload(HeaderBytes, EncryptedPayload, PacketNumber);
            State = PacketState.Decrypted;
        }
    }

    internal enum PacketState
    {
        Decrypted,
        Encrypted
    }
}

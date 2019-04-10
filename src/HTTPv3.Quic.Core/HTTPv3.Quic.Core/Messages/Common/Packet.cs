using HTTPv3.Quic.Messages.Client;
using HTTPv3.Quic.Messages.Frames;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal ref struct Packet
    {
        public Span<byte> Bytes;
        public Span<byte> Payload;
        public Span<byte> PayloadCursor;
        public bool IsServer;
        public PacketState State;
        public Connection Connection;

        public LongHeader LongHeader;
        public Initial Initial;
        public Handshake Handshake;

        public ReadOnlySpan<byte> HeaderProtectionMask;
        public Span<byte> StartOfPayload;

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
            State = PacketState.Encrypted;
            HeaderProtectionMask = null;
            StartOfPayload = null;
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
                        p.DecryptPayLoad();
                        break;
                    case LongHeaderPacketTypes.Handshake:
                        p.Handshake = new Handshake(ref p);
                        p.HeaderProtectionMask = p.Handshake.ComputeDecryptionHeaderProtectionMask(ref p);
                        p.LongHeader.RemoveHeaderProtection(ref p);

                        p.Handshake.RemoveHeaderProtection(ref p);
                        //p.DecryptPayLoad();
                        break;
                }
            }

            return p;
        }

        public object ReadNextFrame()
        {
            if (PayloadCursor == null || PayloadCursor.Length == 0)
                return null;

            byte frameType;
            PayloadCursor = PayloadCursor.ReadNextByte(out frameType);
            if (frameType == 0x02)
            {
                PayloadCursor = PayloadCursor.Slice(4);
                return null;
                //return new AckFrame(ref this);
            }
            if (frameType == 0x06)
                return new CryptoFrame(ref this);

            return null;
        }

        private void DecryptPayLoad()
        {
            int headerLength = Bytes.Length - StartOfPayload.Length;
            PayloadCursor = Payload = Connection.CurrentKeys.DecryptPayload(Bytes.Slice(0, headerLength), StartOfPayload, Initial.PacketNumber);
            State = PacketState.Decrypted;
        }
    }

    internal enum PacketState
    {
        Decrypted,
        Encrypted
    }
}

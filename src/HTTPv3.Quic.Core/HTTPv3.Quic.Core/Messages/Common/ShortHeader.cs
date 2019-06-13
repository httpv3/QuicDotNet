using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Extensions;
using System;

namespace HTTPv3.Quic.Messages.Common
{
    // IETF quic-transport draft-19
    // 17.3.  Short Header Packets
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-17.3
    internal ref struct ShortHeader
    {
        public readonly ReadOnlySpan<byte> HeaderBytes;
        public readonly ReadOnlySpan<byte> DestinationConnID;
        public readonly Span<byte> StartOfPacketNumber;


        public ShortHeader(ref Packet packet)
        {
            if ((packet.Bytes[Header.FixedBit_Offset] & Header.FixedBit_Mask) == 0) throw new ShortHeaderParsingException("Fixed bit is 0.");

            var expectedDestionationId = packet.Connection.MyConnectionId;
            int DCIL = expectedDestionationId.ConnectionIdBytes.Length;

            int destionationConnIdOffset = 1;
            var length = destionationConnIdOffset + DCIL;

            HeaderBytes = packet.Bytes.Slice(0, length);

            DestinationConnID = DCIL == 0 ? ReadOnlySpan<byte>.Empty : packet.Bytes.Slice(destionationConnIdOffset, DCIL);

            StartOfPacketNumber = packet.Bytes.Slice(length);
        }

        internal void RemoveHeaderProtection(ref Packet p)
        {
            p.Bytes[0] ^= (byte)(p.HeaderProtectionMask[0] & 0x1F);

            var packetNumLength = (HeaderBytes[Header.PacketNumberLength_Offset] & Header.PacketNumberLength_Mask) + 1;

            for (int i = 0, j = 1; i < packetNumLength; i++, j++)
                StartOfPacketNumber[i] ^= p.HeaderProtectionMask[j];

            var startOfPayload = StartOfPacketNumber.ReadNumber(packetNumLength, out p.PacketNumber);
            p.HeaderBytes = p.Bytes.Slice(0, p.Bytes.Length - startOfPayload.Length);
            p.EncryptedPayload = startOfPayload;
            p.Bytes = Span<byte>.Empty;
        }


        public ReadOnlySpan<byte> ComputeDecryptionHeaderProtectionMask(ref Packet p)
        {
            var sample = StartOfPacketNumber.Slice(4, 16);
            return p.Connection.KeyManager.Application.ComputeDecryptionHeaderProtectionMask(sample);
        }


        public ReadOnlySpan<byte> ComputeEncryptionHeaderProtectionMask(ref Packet p)
        {
            var sample = StartOfPacketNumber.Slice(4, 16);
            return p.Connection.KeyManager.Application.ComputeEncryptionHeaderProtectionMask(sample);
        }
    }
}

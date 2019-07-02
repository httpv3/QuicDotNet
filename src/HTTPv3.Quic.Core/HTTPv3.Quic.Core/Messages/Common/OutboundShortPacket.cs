using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Security;
using System;

namespace HTTPv3.Quic.Messages.Common
{
    class OutboundShortPacket : OutboundPacket
    {
        public ReadOnlyMemory<byte> Payload;

        public OutboundShortPacket(Connection conn, uint packetNumber, ReadOnlyMemory<byte> payload) : base(conn, packetNumber)
        {
            Payload = payload;
        }

        public Span<byte> Write(in Span<byte> buffer, EncryptionKeys keys)
        {
            byte firstByte = 0x40;
            int pnLen = GetPacketNumberLength();
            firstByte ^= (byte)(pnLen - 1);

            var cur = buffer.Write(firstByte);
            var startOfPN = cur = conn.OtherConnectionId.Write(cur);

            cur = cur.Write(packetNumber, pnLen);

            var header = buffer.Subtract(cur);

            var encryptedPayload = keys.EncryptPayload(header, Payload.Span, packetNumber);

            cur = cur.Write(encryptedPayload);

            var sample = encryptedPayload.AsSpan().Slice(4 - pnLen, 16);
            var mask = keys.ComputeEncryptionHeaderProtectionMask(sample);

            header[0] ^= (byte)(mask[0] & 0x1f);
            for (int i = 0; i < pnLen; i++)
                startOfPN[i] ^= mask[1 + i];

            return cur;
        }
    }
}

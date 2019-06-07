using HTTPv3.Quic.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    class OutboundInitialPacket : OutboundLongPacket
    {
        public ReadOnlyMemory<byte> Payload;
        public byte[] Token;

        public OutboundInitialPacket(Connection conn, uint packetNumber, ReadOnlyMemory<byte> payload, byte[] token = null) : base(conn, packetNumber)
        {
            Payload = payload;
            Token = token;
        }

        public Span<byte> Write(in Span<byte> buffer, EncryptionKeys keys)
        {
            byte firstByte = 0xf0;
            int pnLen = GetPacketNumberLength();
            firstByte |= (byte)pnLen;

            var cur = buffer.Write(firstByte);

            cur = base.Write(cur);

            var startOfPN = cur = cur.WriteVarLengthInt(Token.Length)
                                     .Write(Token)
                                     .WriteVarLengthInt(pnLen + Payload.Length);

            cur = cur.Write(packetNumber, pnLen);

            var header = buffer.Subtract(cur);

            var encryptedPayload = keys.EncryptPayload(header, Payload.Span, packetNumber);

            cur = cur.Write(encryptedPayload);

            var sample = encryptedPayload.AsSpan().Slice(4 - pnLen, 16);
            var mask = keys.ComputeEncryptionHeaderProtectionMask(sample);

            header[0] |= (byte)(mask[0] & 0xf);
            for (int i = 0; i < pnLen; i++)
                startOfPN[i] |= mask[1 + i];

            return cur;
        }
    }
}

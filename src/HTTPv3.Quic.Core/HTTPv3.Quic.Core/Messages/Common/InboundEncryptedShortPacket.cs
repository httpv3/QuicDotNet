using HTTPv3.Quic.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundEncryptedShortPacket : InboundEncryptedPacket
    {
        internal static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> start, in ReadOnlyMemory<byte> current, out InboundEncryptedPacket packetOut)
        {
            var packet = new InboundEncryptedShortPacket()
            {
                AllBytes = start
            };
            packetOut = packet;

            packet.ProtectedPNandPayload = current.Read(ConnectionId.DefaultLength, out packet.DestId);

            return ReadOnlyMemory<byte>.Empty;
        }

        public override void RemoveHeaderProtection(EncryptionKeys keys)
        {
            if (!IsProtected) return;

            var span = ProtectedPNandPayload.Span;
            var sample = span.Slice(4, 16);
            var mask = keys.ComputeDecryptionHeaderProtectionMask(sample);

            AllBytes.Read(out byte firstByte);

            firstByte ^= (byte)(mask[0] & 0x1F);

            var pnNumBytes = (firstByte & 0x03) + 1;

            var startOfPacketNumber = AllBytes.Length - ProtectedPNandPayload.Length;
            unprotectedHeader = AllBytes.Slice(0, startOfPacketNumber + pnNumBytes).ToArray();

            unprotectedHeader[0] = firstByte;

            for (int i = 0; i < pnNumBytes; i++)
            {
                unprotectedHeader[startOfPacketNumber + i] ^= mask[i + 1];
                packetNum = (packetNum << 8) + unprotectedHeader[startOfPacketNumber + i];
            }

            encryptedPayload = ProtectedPNandPayload.Slice(pnNumBytes);

            IsProtected = false;
        }
    }
}

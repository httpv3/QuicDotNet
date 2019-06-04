using HTTPv3.Quic.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal abstract class InboundEncryptedLongPacket : InboundEncryptedPacket
    {
        public ReadOnlyMemory<byte> Version;
        public ReadOnlyMemory<byte> SrcId;

        internal static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> start, in ReadOnlyMemory<byte> current, byte firstByte, out InboundEncryptedPacket packetOut)
        {
            var cur = current.Read(Header.Version_Length, out ReadOnlyMemory<byte> version)
                             .Read(out byte DCIL_SCIL);

            int DCIL = LongHeader.ParseConnIDLength((byte)((DCIL_SCIL & Header.DCIL_Mask) >> Header.DCIL_Shift));
            int SCIL = LongHeader.ParseConnIDLength((byte)(DCIL_SCIL & Header.SCIL_Mask));

            cur = cur.Read(DCIL, out ReadOnlyMemory<byte> destId)
                     .Read(SCIL, out ReadOnlyMemory<byte> srcId);

            var type = (byte)((firstByte & Header.LongPacketType_Mask) >> Header.LongPacketType_Shift);

            InboundEncryptedLongPacket packet;

            switch (type)
            {
                case 0:
                    cur = InboundEncryptedInitialPacket.Parse(cur, out packet);
                    break;
                case 1:
                    cur = InboundEncrypted0RTTPacket.Parse(cur, out packet);
                    break;
                case 2:
                    cur = InboundEncryptedHandshakePacket.Parse(cur, out packet);
                    break;
                case 3:
                default:
                    throw new NotImplementedException();
            }

            packet.AllBytes = start.Slice(0, start.Length - cur.Length);
            packet.Version = version;
            packet.DestId = destId;
            packet.SrcId = srcId;

            packetOut = packet;
            return cur;
        }

        protected override void RemoveHeaderProtection(EncryptionKeys keys)
        {
            if (!IsProtected) return;

            var span = ProtectedPNandPayload.Span;
            var sample = span.Slice(4, 16);
            var mask = keys.ComputeDecryptionHeaderProtectionMask(sample);

            AllBytes.Read(out byte firstByte);

            firstByte ^= (byte)(mask[0] & 0x0F);

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

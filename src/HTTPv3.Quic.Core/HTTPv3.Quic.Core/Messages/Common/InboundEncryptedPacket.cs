using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal ref struct InboundEncryptedPacket
    {
        public byte FirstByte;
        public byte LongHeaderType;
        public ReadOnlySpan<byte> ExtraHeader;
        public ReadOnlySpan<byte> ProtectedPNandPayload;
        public ReadOnlySpan<byte> DestId;
        public ReadOnlySpan<byte> SrcId;

        internal static ReadOnlySpan<byte> Parse(in ReadOnlySpan<byte> data, out InboundEncryptedPacket packet)
        {
            packet = new InboundEncryptedPacket();

            var cur = data.Read(out packet.FirstByte);

            if (Header.IsLongHeader(packet.FirstByte))
            {
                cur = cur.Skip(Header.Version_Length)
                         .Read(out byte DCIL_SCIL);

                int DCIL = LongHeader.ParseConnIDLength((byte)((DCIL_SCIL & Header.DCIL_Mask) >> Header.DCIL_Shift));
                int SCIL = LongHeader.ParseConnIDLength((byte)(DCIL_SCIL & Header.SCIL_Mask));

                cur = cur.Read(DCIL, out packet.DestId)
                         .Read(SCIL, out packet.SrcId);

                packet.LongHeaderType = (byte)((packet.FirstByte & Header.LongPacketType_Mask) >> Header.LongPacketType_Shift)

                switch(packet.LongHeaderType)
                {
                    case 0:
                        var startOfExtra = cur;
                        var endOfExtra = startOfExtra.ReadNextVariableInt(out int tLen).Skip(tLen);

                        packet.ExtraHeader = startOfExtra.Subtract(endOfExtra);

                        cur = endOfExtra.ReadNextVariableInt(out int len)
                                        .Read(len, out packet.ProtectedPNandPayload);
                        break;
                    case 1:
                    case 2:
                        cur = cur.ReadNextVariableInt(out int len2)
                                 .Read(len2, out packet.ProtectedPNandPayload);
                        break;
                    case 3:
                        throw new NotImplementedException();
                        break;
                }
            }
            else
            {
                cur = cur.Read(ConnectionId.DefaultLength, out packet.DestId);
                packet.ProtectedPNandPayload = cur;
                return Span<byte>.Empty;
            }
        }
    }
}

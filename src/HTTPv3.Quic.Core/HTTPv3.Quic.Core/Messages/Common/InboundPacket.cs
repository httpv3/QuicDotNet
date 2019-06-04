using HTTPv3.Quic.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundPacket
    {
        public InboundEncryptedPacket EncryptedPacket;

        public ReadOnlyMemory<byte> Payload;

        public InboundPacket (InboundEncryptedPacket packet, EncryptionKeys keys)
        {
            EncryptedPacket = packet;

            Payload = keys.DecryptPayload(packet.UnprotectedHeader, packet.EncryptedPayload.Span, packet.PacketNum);
        }

        public IEnumerable<InboundEncryptedPacket> AsFrames()
        {
            var cur = Data;
            while (cur.Length > 0)
            {
                cur = InboundEncryptedPacket.Parse(cur, out var p);
                p.InboundDatagram = this;
                yield return p;
            }
        }
    }
}

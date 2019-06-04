using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundDatagram
    {
        public ReadOnlyMemory<byte> Data;
        public DateTime Recieved = DateTime.UtcNow;
        public DateTime Processed;

        public IEnumerable<InboundEncryptedPacket> AsPackets()
        {
            var cur = Data;
            while(cur.Length > 0)
            {
                cur = InboundEncryptedPacket.Parse(cur, out var p);
                p.InboundDatagram = this;
                yield return p;
            }
        }
    }
}

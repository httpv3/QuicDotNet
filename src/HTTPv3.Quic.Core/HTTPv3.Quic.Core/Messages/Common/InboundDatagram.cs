using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundDatagram
    {
        public ReadOnlyMemory<byte> Data;

        public IEnumerable<InboundEncryptedPacket> AsPackets()
        {
            var cur = Data;
            while(cur.Length > 0)
            {
                cur = InboundEncryptedPacket.Parse(cur, out var p);
                yield return p;
            }
        }
    }
}

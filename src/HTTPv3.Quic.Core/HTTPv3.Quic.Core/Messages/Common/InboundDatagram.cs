using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundDatagram
    {
        public ReadOnlyMemory<byte> Data;
        public DateTime Recieved = DateTime.UtcNow;

        public InboundDatagram(ReadOnlyMemory<byte> data)
        {
            Data = data;
        }

        public IEnumerable<InboundEncryptedPacket> AsPackets()
        {
            var cur = Data;
            while (cur.Length > 0)
            {
                InboundEncryptedPacket p;

                try
                {
                    cur = InboundEncryptedPacket.Parse(cur, out p);
                    if (p == null)
                        yield break;
                }
                catch
                {
                    yield break;
                }

                p.InboundDatagram = this;
                yield return p;
            }
        }
    }

    internal static class InboundDatagramExtension
    {
        public static async IAsyncEnumerable<InboundEncryptedPacket> AsPackets(this IAsyncEnumerable<InboundDatagram> datagrams)
        {
            await foreach (var d in datagrams)
            {
                foreach (var p in d.AsPackets())
                    yield return p;
            }
        }
    }
}

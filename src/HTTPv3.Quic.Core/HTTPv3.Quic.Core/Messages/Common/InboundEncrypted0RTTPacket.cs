using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundEncrypted0RTTPacket : InboundEncryptedLongPacket
    {
        internal static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> current, out InboundEncryptedLongPacket packetOut)
        {
            var packet = new InboundEncrypted0RTTPacket();
            packetOut = packet;

            var cur = current.ReadNextVariableInt(out int len)
                             .Read(len, out packet.ProtectedPNandPayload);

            return cur;
        }
    }
}

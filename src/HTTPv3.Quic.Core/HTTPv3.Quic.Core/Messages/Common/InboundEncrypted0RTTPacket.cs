using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Security;
using System;

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

        public override InboundPacket AsDecryptedPacket(KeyManager keyMan)
        {
            var keys = keyMan.Initial;
            RemoveHeaderProtection(keys);
            return new InboundPacket(this, keys);
        }
    }
}

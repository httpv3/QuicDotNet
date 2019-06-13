using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Security;
using System;

namespace HTTPv3.Quic.Messages.Common
{
    internal class InboundEncryptedInitialPacket : InboundEncryptedLongPacket
    {
        public ReadOnlyMemory<byte> Token;

        internal static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> current, out InboundEncryptedLongPacket packetOut)
        {
            var packet = new InboundEncryptedInitialPacket();
            packetOut = packet;

            var cur = current.ReadNextVariableInt(out int tokenLength).Read(tokenLength, out packet.Token);

            cur = cur.ReadNextVariableInt(out int len)
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

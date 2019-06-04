using HTTPv3.Quic.Exceptions.Security;
using HTTPv3.Quic.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Common
{
    internal abstract class InboundEncryptedPacket
    {
        public bool IsProtected = true;
        public ReadOnlyMemory<byte> DestId;
        public ReadOnlyMemory<byte> ProtectedPNandPayload;
        public ReadOnlyMemory<byte> AllBytes;

        protected uint packetNum = 0;
        public uint PacketNum => IsProtected ? throw new PacketProtectedException("") : packetNum;

        protected ReadOnlyMemory<byte> encryptedPayload;
        public ReadOnlyMemory<byte> EncryptedPayload => IsProtected ? throw new PacketProtectedException("") : encryptedPayload;

        protected byte[] unprotectedHeader;
        public byte[] UnprotectedHeader => IsProtected ? throw new PacketProtectedException("") : unprotectedHeader;

        internal static ReadOnlyMemory<byte> Parse(in ReadOnlyMemory<byte> start, out InboundEncryptedPacket packet)
        {
            var cur = start.Read(out byte firstByte);

            if (Header.IsLongHeader(firstByte))
            {
                return InboundEncryptedLongPacket.Parse(start, cur, firstByte, out packet);
            }
            else
            {
                return InboundEncryptedShortPacket.Parse(start, cur, out packet);
            }
        }

        public abstract void RemoveHeaderProtection(EncryptionKeys keys);
    }
}

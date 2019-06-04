﻿using HTTPv3.Quic.Messages.Frames;
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

        public IEnumerable<IFrame> AsFrames()
        {
            var cur = Payload;
            while (cur.Length > 0)
            {
                IFrame f = null;

                cur = cur.Read(out FrameType type);

                switch(type)
                {
                    case FrameType.Padding:
                        continue;
                    case FrameType.Crypto:
                        cur = CryptoFrame.Parse(cur, out f);
                        break;
                    default:
                        throw new NotImplementedException();
                }

                if (f != null)
                    yield return f;
            }
        }
    }

    internal static class InboundPacketExtension
    {
        public static async IAsyncEnumerable<IFrame> AsFrames(this IAsyncEnumerable<InboundPacket> packets)
        {
            await foreach (var p in packets)
            {
                foreach (var f in p.AsFrames())
                    yield return f;
            }
        }
    }
}

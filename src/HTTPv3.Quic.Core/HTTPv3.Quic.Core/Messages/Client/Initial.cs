using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Client
{
    internal readonly ref struct Initial
    {
        public readonly ReadOnlySpan<byte> Token;

        public readonly int Length;

        public readonly uint PacketNumber;


        public Initial(ReadOnlySpan<byte> packet, LongHeader header)
        {
            if (header.LongPacketType != LongHeaderPacketTypes.Initial) throw new InitialParsingException($"Long Header is of type {header.LongPacketType}");

            var afterHeader = packet.Slice(header.Length);


            int tokenLength;
            int packetNumLength = LongHeader.ParsePacketNumberLength(packet);

            var payload = afterHeader.ReadNextVariableInt(out tokenLength)
                                     .ReadNextBytes(tokenLength, out Token)
                                     .ReadNextVariableInt(out Length)
                                     .ReadNextNumber(packetNumLength, out PacketNumber);


        }
    }
}

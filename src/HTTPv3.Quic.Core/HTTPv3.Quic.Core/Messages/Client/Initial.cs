﻿using HTTPv3.Quic.Exceptions.Parsing;
using HTTPv3.Quic.Messages.Common;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Messages.Client
{
    internal ref struct Initial
    {
        public readonly Span<byte> Token;

        public readonly int PayloadAndPacketNumberLength;

        public int PacketNumLength;
        public uint PacketNumber;

        public readonly Span<byte> StartOfPacketNumber;

        public Initial(ref Packet packet)
        {
            if (packet.LongHeader.LongPacketType != LongHeaderPacketTypes.Initial) throw new InitialParsingException($"Long Header is of type {packet.LongHeader.LongPacketType}");

            Span<byte> afterHeader = packet.Bytes.Slice(packet.LongHeader.HeaderBytes.Length);


            int tokenLength;

            StartOfPacketNumber = afterHeader.ReadNextVariableInt(out tokenLength)
                                     .ReadNextBytes(tokenLength, out Token)
                                     .ReadNextVariableInt(out PayloadAndPacketNumberLength);

            PacketNumLength = 0;
            PacketNumber = 0;
        }

        internal void RemoveHeaderProtection(ref Packet p)
        {
            PacketNumLength = (p.LongHeader.HeaderBytes[Header.PacketNumberLength_Offset] & Header.PacketNumberLength_Mask) + 1;

            for (int i = 0, j = 1; i < PacketNumLength; i++, j++)
                StartOfPacketNumber[i] ^= p.HeaderProtectionMask[j];

            p.StartOfPayload = StartOfPacketNumber.ReadNextNumber(PacketNumLength, out PacketNumber);
        }


        public ReadOnlySpan<byte> ComputeDecryptionHeaderProtectionMask(ref Packet p)
        {
            var sample = StartOfPacketNumber.Slice(4, 16);
            return p.Connection.CurrentKeys.ComputeDecryptionHeaderProtectionMask(sample);
        }


        public ReadOnlySpan<byte> ComputeEncryptionHeaderProtectionMask(ref Packet p)
        {
            var sample = StartOfPacketNumber.Slice(4, 16);
            return p.Connection.CurrentKeys.ComputeEncryptionHeaderProtectionMask(sample);
        }
    }
}

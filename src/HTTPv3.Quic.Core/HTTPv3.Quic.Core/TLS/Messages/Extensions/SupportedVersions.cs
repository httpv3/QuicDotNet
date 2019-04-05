﻿using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal class SupportedVersions : Extension
    {
        public const int ArrayLength_NumBytes = 1;
        public const int SupportedVersionLength_NumBytes = 2;

        public List<ProtocolVersion> Versions = new List<ProtocolVersion>();

        public SupportedVersions(ReadOnlySpan<byte> data) : base(ExtensionType.SupportedVersions)
        {
            data.ReadNextTLSVariableLength(ArrayLength_NumBytes, out var arrData);

            while(!arrData.IsEmpty)
            {
                arrData = arrData.ReadNextNumber(SupportedVersionLength_NumBytes, out var val);

                if (Enum.IsDefined(typeof(ProtocolVersion), (ushort)val))
                    Versions.Add((ProtocolVersion)Enum.ToObject(typeof(ProtocolVersion), (ushort)val));
            }
        }
    }
}

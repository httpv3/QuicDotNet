using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    public class UnknownExtension
    {
        public const int ArrayLength_NumBytes = 2;

        public ushort ExtensionType;
        public byte[] Bytes;
    }
}

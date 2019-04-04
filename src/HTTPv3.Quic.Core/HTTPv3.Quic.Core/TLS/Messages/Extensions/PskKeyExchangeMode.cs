using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    internal enum PskKeyExchangeMode : byte
    {
        PSKOnlyKeyEstablishment = 0,
        PSKwithDheKeyEstablishment = 1,
    }
}

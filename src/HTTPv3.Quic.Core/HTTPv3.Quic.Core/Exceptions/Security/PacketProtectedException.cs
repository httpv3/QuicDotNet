using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Security
{
    public class PacketProtectedException : SecurityException
    {
        public PacketProtectedException(string message) : base(message) { }
    }
}

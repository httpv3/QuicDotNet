using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Security
{
    public class SecurityException : Exception
    {
        public SecurityException(string message) : base(message) { }
    }
}

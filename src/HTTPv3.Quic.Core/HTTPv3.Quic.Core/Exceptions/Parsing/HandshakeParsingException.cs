using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class HandshakeParsingException : ParsingException
    {
        public HandshakeParsingException(string message) : base(message) { }
    }
}

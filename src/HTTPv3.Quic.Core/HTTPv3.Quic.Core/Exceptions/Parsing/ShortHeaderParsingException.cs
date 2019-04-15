using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class ShortHeaderParsingException : ParsingException
    {
        public ShortHeaderParsingException(string message) : base(message) { }
    }
}

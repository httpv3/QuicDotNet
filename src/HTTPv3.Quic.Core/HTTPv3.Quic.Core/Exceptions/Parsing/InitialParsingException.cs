using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class InitialParsingException : ParsingException
    {
        public InitialParsingException(string message) : base(message) { }
    }
}

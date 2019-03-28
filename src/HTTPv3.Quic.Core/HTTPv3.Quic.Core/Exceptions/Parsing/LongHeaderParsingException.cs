using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class LongHeaderParsingException : ParsingException
    {
        public LongHeaderParsingException(string message) : base(message) { }
    }
}

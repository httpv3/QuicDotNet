using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class SmallHeaderParsingException : ParsingException
    {
        public SmallHeaderParsingException(string message) : base(message) { }
    }
}

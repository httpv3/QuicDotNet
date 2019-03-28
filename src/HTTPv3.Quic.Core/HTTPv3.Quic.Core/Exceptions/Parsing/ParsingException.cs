using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class ParsingException : Exception
    {
        public ParsingException(string message) : base(message) { }
    }
}

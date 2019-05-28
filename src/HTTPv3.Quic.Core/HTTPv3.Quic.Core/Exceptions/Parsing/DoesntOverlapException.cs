using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class DoesntOverlapException : ParsingException
    {
        public DoesntOverlapException(string message) : base(message) { }
    }
}

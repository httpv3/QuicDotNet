using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Exceptions.Parsing
{
    public class NotEnoughBytesException : ParsingException
    {
        public NotEnoughBytesException(string message) : base(message) { }
    }
}

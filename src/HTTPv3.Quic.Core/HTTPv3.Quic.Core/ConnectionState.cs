using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic
{
    public enum ConnectionState
    {
        NotConnected = 0,
        Connecting,
        Connected,
        Disconnecting
    }
}

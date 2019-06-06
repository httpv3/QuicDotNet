using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    public enum EncryptionState
    {
        Initial = 0,
        Handshake = 1,
        Application = 2
    }
}

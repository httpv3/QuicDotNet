using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    public enum EncryptionState
    {
        Initial,
        Handshake,
        Application
    }
}

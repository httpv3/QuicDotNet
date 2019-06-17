using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    internal class CipherUpdateDetail
    {
        public EncryptionState State;
        public byte[] ClientSecret;
        public byte[] ServerSecret;
        public CipherSuite CipherSuite;
    }
}

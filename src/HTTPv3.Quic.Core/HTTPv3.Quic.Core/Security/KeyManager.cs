using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.Security
{
    class KeyManager
    {
        internal List<ApplicationKeys> applicationKeys = new List<ApplicationKeys>();
        internal List<HandshakeKeys> handshakeKeys = new List<HandshakeKeys>();
        public readonly InitialKeys Initial;

        public ApplicationKeys Application { get => applicationKeys.Count > 0 ? applicationKeys[0] : null; }
        public HandshakeKeys Handshake { get => handshakeKeys.Count > 0 ? handshakeKeys[0] : null; }

        public KeyManager(byte[] clientChosenDestinationId, bool isServer)
        {
            Initial = InitialKeys.Create(clientChosenDestinationId, isServer);
        }

        public void Add(CipherUpdateDetail detail)
        {
            Add(detail.State, detail.ClientSecret, detail.ServerSecret, detail.CipherSuite);
        }

        public void Add(EncryptionState state, in byte[] mySecret, in byte[] theirSecret, CipherSuite cipherSuite)
        {
            switch (state)
            {
                case EncryptionState.Handshake:
                    handshakeKeys.Add(new HandshakeKeys(mySecret, theirSecret, cipherSuite));
                    break;
                case EncryptionState.Application:
                    applicationKeys.Add(new ApplicationKeys(mySecret, theirSecret, cipherSuite));
                    break;
            }
        }
    }
}

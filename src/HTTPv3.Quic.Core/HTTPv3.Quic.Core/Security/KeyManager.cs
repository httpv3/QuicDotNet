using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace HTTPv3.Quic.Security
{
    class KeyManager
    {
        internal List<ApplicationKeys> applicationKeys = new List<ApplicationKeys>();
        internal List<HandshakeKeys> handshakeKeys = new List<HandshakeKeys>();
        public readonly InitialKeys Initial;

        public TaskCompletionSource<ApplicationKeys> tscApplicationKey = new TaskCompletionSource<ApplicationKeys>();
        public Task<ApplicationKeys> currentApplicationKeyTask;

        public TaskCompletionSource<HandshakeKeys> tscHandshakeKey = new TaskCompletionSource<HandshakeKeys>();
        public Task<HandshakeKeys> currentHandshakeKeyTask;

        public Task<ApplicationKeys> Application { get => currentApplicationKeyTask; }
        public Task<HandshakeKeys> Handshake { get => currentHandshakeKeyTask; }

        public KeyManager(byte[] clientChosenDestinationId, bool isServer)
        {
            Initial = InitialKeys.Create(clientChosenDestinationId, isServer);
            currentApplicationKeyTask = tscApplicationKey.Task;
            currentHandshakeKeyTask = tscHandshakeKey.Task;
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
                    var key = new HandshakeKeys(mySecret, theirSecret, cipherSuite);
                    handshakeKeys.Add(key);
                    if (tscHandshakeKey != null)
                    {
                        tscHandshakeKey.SetResult(key);
                        tscHandshakeKey = null;
                    }
                    else
                    {
                        currentHandshakeKeyTask = Task.FromResult(key);
                    }
                    break;
                case EncryptionState.Application:
                    var key2 = new ApplicationKeys(mySecret, theirSecret, cipherSuite);
                    applicationKeys.Add(key2);
                    if (tscApplicationKey != null)
                    {
                        tscApplicationKey.SetResult(key2);
                        tscApplicationKey = null;
                    }
                    else
                    {
                        currentApplicationKeyTask = Task.FromResult(key2);
                    }
                    break;
            }
        }
    }
}

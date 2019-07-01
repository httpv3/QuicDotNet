using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.Messages.Client;
using HTTPv3.Quic.Messages.Extensions;
using HTTPv3.Quic.Messages.Frames;
using HTTPv3.Quic.Security;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class Connection
    {
        private const int MINIMUM_INITIAL_PAYLOAD_SIZE = 1180;

        public UdpClient udpClient;
        public CancellationToken Cancel;

        public ConnectionState ConnectionState { get; private set; } = ConnectionState.NotConnected;

        public ClientConnectionId ClientConnectionId;
        public ServerConnectionId ServerConnectionId;
        public string ServerName;

        internal KeyManager KeyManager;

        internal TLS.ClientConnection TLSConn;

        public bool IsServer = false;

        public ConnectionId MyConnectionId { get { return IsServer ? ServerConnectionId as ConnectionId : ClientConnectionId as ConnectionId; } }
        public ConnectionId OtherConnectionId { get { return IsServer ? ClientConnectionId as ConnectionId : ServerConnectionId as ConnectionId; } }

        internal AckStream InitialAckStream;
        internal AckStream HandshakeAckStream;
        internal AckStream ApplicationAckStream;

        internal CryptoStream InitialCryptoStream;
        internal CryptoStream HandshakeCryptoStream;
        internal CryptoStream ApplicationCryptoStream;

        private Receiver receiver;
        private InitialSender initialSender;
        private HandshakeSender handshakeSender;
        private ApplicationSender applicationSender;

        private Task receiverTask;
        private Task senderTask;

        internal Connection(byte[] clientChosenDestinationId, string serverName, bool isServer, UdpClient udpClient, CancellationToken cancel = default)
        {
            this.udpClient = udpClient;
            Cancel = cancel;
            ServerName = serverName;
            IsServer = isServer;

            KeyManager = new KeyManager(clientChosenDestinationId, isServer);
        }

        internal async Task SendConnect()
        {
            InitialAckStream = new AckStream(Cancel);
            HandshakeAckStream = new AckStream(Cancel);
            ApplicationAckStream = new AckStream(Cancel);

            InitialCryptoStream = new CryptoStream(Cancel);
            HandshakeCryptoStream = new CryptoStream(Cancel);
            ApplicationCryptoStream = new CryptoStream(Cancel);

            TLSConn = new TLS.ClientConnection(InitialCryptoStream, HandshakeCryptoStream, ApplicationCryptoStream, OnCipherUpdated, Cancel);

            receiverTask = StartReceiving();
            senderTask = StartSending();

            var buffer = new byte[1500];

            WriteConnect(buffer, out int len);

            await initialSender.SendData(buffer.AsMemory().Slice(0, len));
        }

        internal void WriteConnect(in Span<byte> buffer, out int length)
        {
            var temp = new byte[1500];
            var after = TLSConn.WriteClientHello(temp, ServerName, TransportParameters.Default.ToUnknownExtension());
            var frameData = temp.AsSpan(0, temp.Length - after.Length);
            CryptoFrame frame = new CryptoFrame(0, frameData.ToArray());

            InitialCryptoStream.AddToFromAppOffset(frameData.Length);

            var curSpan = frame.Write(buffer, false);
            length = buffer.Length - curSpan.Length;

            if (length > MINIMUM_INITIAL_PAYLOAD_SIZE) //No Padding needed.
                return;

            buffer.PadToLength(length, MINIMUM_INITIAL_PAYLOAD_SIZE);
            length = MINIMUM_INITIAL_PAYLOAD_SIZE;
        }

        private Task StartReceiving()
        {
            receiver = new Receiver(udpClient, this);
            return receiver.Run();
        }

        private Task StartSending()
        {
            initialSender = new InitialSender(udpClient, this);
            handshakeSender = new HandshakeSender(udpClient, this);
            applicationSender = new ApplicationSender(udpClient, this);

            return Task.WhenAll(initialSender.Run(), handshakeSender.Run(), applicationSender.Run());
        }

        private void OnCipherUpdated(CipherUpdateDetail detail)
        {
            KeyManager.Add(detail);
        }
    }
}

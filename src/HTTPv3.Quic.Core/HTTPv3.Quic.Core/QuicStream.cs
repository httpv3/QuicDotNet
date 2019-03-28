using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace HTTPv3.Quic
{
    public class QuicStream : NetworkStream
    {
        public QuicStream(Socket socket) : base(socket)
        {
        }

        public QuicStream(Socket socket, bool ownsSocket) : base(socket, ownsSocket)
        {
        }

        public QuicStream(Socket socket, FileAccess access) : base(socket, access)
        {
        }

        public QuicStream(Socket socket, FileAccess access, bool ownsSocket) : base(socket, access, ownsSocket)
        {
        }
    }
}

using Org.BouncyCastle.Security;
using System;
using System.Data.HashFunction.FNV;
using System.Linq;

namespace HTTPv3.Quic
{
    public class ConnectionId
    {
        public readonly static ConnectionId Empty = new ConnectionId(new byte[0]);

        public const int DefaultLength = 4;
        private static SecureRandom prng = new SecureRandom();
        private static IFNV1 Hasher = FNV1Factory.Instance.Create(FNVConfig.GetPredefinedConfig(32));
        public readonly byte[] ConnectionIdBytes;
        public readonly int HashCode;

        public ConnectionId(byte[] connectionIdBytes)
        {
            ConnectionIdBytes = connectionIdBytes;

            if (ConnectionIdBytes.Length == 0)
                HashCode = 0;
            else
                HashCode = Hasher.ComputeHash(connectionIdBytes).Hash.ToInt32(true);
        }

        protected static byte[] GenerateBytes(int length = DefaultLength)
        {
            return SecureRandom.GetNextBytes(prng, length);
        }

        public override int GetHashCode()
        {
            return HashCode;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, Empty))
                return ReferenceEquals(obj, Empty);
            if (ReferenceEquals(obj, Empty))
                return ReferenceEquals(this, Empty);

            if (ReferenceEquals(this, obj)) return true;
            if (ReferenceEquals(ConnectionIdBytes, obj)) return true;

            if (obj.GetType() == typeof(byte[]))
            {
                byte[] arr = obj as byte[];
                return ConnectionIdBytes.SequenceEqual(arr);
            }

            var connId = obj as ConnectionId;
            if (connId != null)
            {
                return ConnectionIdBytes.SequenceEqual(connId.ConnectionIdBytes);
            }

            return false;
        }

        public override string ToString()
        {
            return BitConverter.ToString(ConnectionIdBytes);
        }
    }
}

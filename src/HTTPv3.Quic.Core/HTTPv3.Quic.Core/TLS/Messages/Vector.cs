using HTTPv3.Quic.Extensions;
using System;
using System.Buffers;

namespace HTTPv3.Quic.TLS.Messages
{
    internal class VectorState
    {
        public int EndLength = 0;
    }

    internal static class VectorExtensions
    {
        public static Span<byte> WriteVector(this in Span<byte> buffer, int vectorLen_numBytes, SpanAction<byte, VectorState> action)
        {
            var state = new VectorState();
            var data = buffer.Slice(vectorLen_numBytes);
            state.EndLength = data.Length;

            action(data, state);

            int bytesUsed = data.Length - state.EndLength;
            buffer.Write(bytesUsed, vectorLen_numBytes);

            return data.Slice(bytesUsed);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public static class UdpClientExtension
    {
        //
        // Summary:
        //     Returns a UDP datagram asynchronously that was sent by a remote host.
        //
        // Parameters:
        //   cancellationToken:
        //     The token to monitor for cancellation requests. The default value is System.Threading.CancellationToken.None.
        //
        // Returns:
        //     Returns System.Threading.Tasks.Task`1. The task object representing the asynchronous
        //     operation.
        //
        // Exceptions:
        //   T:System.ObjectDisposedException:
        //     The underlying System.Net.Sockets.Socket has been closed.
        //
        //   T:System.Net.Sockets.SocketException:
        //     An error occurred when accessing the socket.
        public static async Task<UdpReceiveResult> ReceiveAsync(this UdpClient client, CancellationToken cancel)
        {
            var tcs = new TaskCompletionSource<UdpReceiveResult>();

            cancel.Register(() =>
            {
                tcs.TrySetCanceled();
            });

            if (cancel.IsCancellationRequested)
                return default;

            var t = client.ReceiveAsync();

            return (await Task.WhenAny(t, tcs.Task)).Result;
        }

    }
}

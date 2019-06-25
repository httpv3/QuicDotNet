using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    class AwaitableQueue<T> : IAsyncEnumerable<T>, IAsyncEnumerator<T>
    {
        ConcurrentQueue<T> q = new ConcurrentQueue<T>();
        TaskCompletionSource<bool> tsc = null;

        public T Current { get; private set; } = default(T);

        public void Add(T item)
        {
            lock (q)
            {
                q.Enqueue(item);

                if (tsc != null && !tsc.Task.IsCompleted)
                {
                    tsc.SetResult(true);
                    tsc = null;
                }
            }
        }

        async ValueTask IAsyncDisposable.DisposeAsync()
        {
            await Task.Delay(0);
            tsc.SetResult(false);
        }

        IAsyncEnumerator<T> IAsyncEnumerable<T>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return this;
        }

        ValueTask<bool> IAsyncEnumerator<T>.MoveNextAsync()
        {
            lock (q)
            {
                if (q.Count == 0)
                {
                    tsc = new TaskCompletionSource<bool>();
                    return new ValueTask<bool>(tsc.Task);
                }

                if (q.TryDequeue(out var item))
                {
                    Current = item;
                }

                return new ValueTask<bool>(true);
            }
        }
    }
}

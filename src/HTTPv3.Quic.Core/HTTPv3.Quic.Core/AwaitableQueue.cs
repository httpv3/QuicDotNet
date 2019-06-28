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
                if (tsc == null)
                {
                    q.Enqueue(item);
                    return;
                }

                Current = item;
                tsc.SetResult(true);
                tsc = null;
            }
        }

        ValueTask IAsyncDisposable.DisposeAsync()
        {
            if (tsc != null)
            {
                tsc.SetResult(false);
                tsc = null;
            }

            return new ValueTask(null);
        }

        IAsyncEnumerator<T> IAsyncEnumerable<T>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return this;
        }

        ValueTask<bool> IAsyncEnumerator<T>.MoveNextAsync()
        {
            lock (q)
            {
                if (q.TryDequeue(out var item))
                {
                    Current = item;
                    tsc = null;
                    return new ValueTask<bool>(true);
                }
                else
                {
                    tsc = new TaskCompletionSource<bool>();
                    return new ValueTask<bool>(tsc.Task);
                }
            }
        }
    }
}

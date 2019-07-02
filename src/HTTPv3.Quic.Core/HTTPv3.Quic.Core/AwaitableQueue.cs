using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HTTPv3.Quic
{
    public class AwaitableQueue<T> : IAsyncEnumerable<T>, IAsyncEnumerator<T>
    {
        private readonly CancellationToken cancel;

        object lockVar = new object();
        ConcurrentQueue<T> q = new ConcurrentQueue<T>();
        TaskCompletionSource<bool> tsc = null;

        public int Backlog => q.Count;

        public T Current { get; private set; } = default(T);

        public AwaitableQueue(CancellationToken cancel = default)
        {
            this.cancel = cancel;
            cancel.Register(()=> { if (tsc != null) tsc.TrySetCanceled(cancel); });
        }

        public void Add(T item)
        {
            lock (lockVar)
            {
                if (tsc == null)
                {
                    q.Enqueue(item);
                    return;
                }

                Current = item;
                var t = tsc;
                tsc = null;
                t.SetResult(true);
            }
        }

        ValueTask IAsyncDisposable.DisposeAsync()
        {
            if (tsc != null)
            {
                var t = tsc;
                tsc = null;
                t.SetResult(false);
            }

            return new ValueTask(null);
        }

        IAsyncEnumerator<T> IAsyncEnumerable<T>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return this;
        }

        ValueTask<bool> IAsyncEnumerator<T>.MoveNextAsync()
        {
            if (cancel.IsCancellationRequested)
                return new ValueTask<bool>(true);

            lock (lockVar)
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

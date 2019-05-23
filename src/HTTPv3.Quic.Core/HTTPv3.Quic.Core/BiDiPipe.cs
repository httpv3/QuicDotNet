using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace HTTPv3.Quic
{
    public class BiDiPipe
    {
        Pipe a;
        Pipe b;

        public BiDiPipe()
        {
            a = new Pipe();
            b = new Pipe();
        }

        public BiDiPipe(PipeOptions options)
        {
            a = new Pipe(options);
            b = new Pipe(options);
        }


    }
}

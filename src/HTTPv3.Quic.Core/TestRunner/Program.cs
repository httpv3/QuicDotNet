using HTTPv3.Quic;
using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace TestRunner
{
    class Program
    {
        static AwaitableQueue<char> q = new AwaitableQueue<char>();

        static async Task Main(string[] args)
        {
            //AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);

            //var client_hello = "01 00 00 c6 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 06 13 01 13 02 13 03 01 00 00 77 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04".ToByteArrayFromHex();
            //var server_hello = "02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 03 04".ToByteArrayFromHex();
            //var all_stream = new byte[client_hello.Length + server_hello.Length];
            //all_stream.AsSpan().Write(client_hello).Write(server_hello);

            //var shared_secret = "df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624".ToByteArrayFromHex();
            //var hello_hash = ComputeSha256Hash(all_stream);  // "da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5".ToByteArrayFromHex();
            //var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();

            //var early_secret = hkdf.Extract(zero_key, new byte[] { 0 });
            //Console.WriteLine($"early_secret: {BitConverter.ToString(early_secret).Replace("-", "")}");

            //var empty_hash = ComputeSha256Hash(new byte[] { });
            //Console.WriteLine($"empty_hash: {BitConverter.ToString(empty_hash).Replace("-", "")}");

            //var derived_secret = ExpandTLSLabel(hkdf, early_secret, DERIVED_LABEL, empty_hash, 32);
            //Console.WriteLine($"derived_secret: {BitConverter.ToString(derived_secret).Replace("-", "")}");

            //var handshake_secret = hkdf.Extract(shared_secret, derived_secret);
            //Console.WriteLine($"handshake_secret: {BitConverter.ToString(handshake_secret).Replace("-", "")}");

            //var client_handshake_traffic_secret = ExpandTLSLabel(hkdf, handshake_secret, CLIENT_HANDSHAKE_LABEL, hello_hash, 32);
            //Console.WriteLine($"csecret: {BitConverter.ToString(client_handshake_traffic_secret).Replace("-", "")}");

            //var server_handshake_traffic_secret = ExpandTLSLabel(hkdf, handshake_secret, SERVER_HANDSHAKE_LABEL, hello_hash, 32);
            //Console.WriteLine($"csecret: {BitConverter.ToString(server_handshake_traffic_secret).Replace("-", "")}");

            //var client_handshake_key = ExpandTLSLabel(hkdf, client_handshake_traffic_secret, KEY_LABEL, new byte[] { }, 16);
            //Console.WriteLine($"ckey: {BitConverter.ToString(client_handshake_key).Replace("-", "")}");

            //var server_handshake_key = ExpandTLSLabel(hkdf, server_handshake_traffic_secret, KEY_LABEL, new byte[] { }, 16);
            //Console.WriteLine($"skey: {BitConverter.ToString(server_handshake_key).Replace("-", "")}");

            //var client_handshake_iv = ExpandTLSLabel(hkdf, client_handshake_traffic_secret, IV_LABEL, new byte[] { }, 12);
            //Console.WriteLine($"civ: {BitConverter.ToString(client_handshake_iv).Replace("-", "")}");

            //var server_handshake_iv = ExpandTLSLabel(hkdf, server_handshake_traffic_secret, IV_LABEL, new byte[] { }, 12);
            //Console.WriteLine($"siv: {BitConverter.ToString(server_handshake_iv).Replace("-", "")}");

            //await Run();


        }

        static public readonly byte[] TLS_LABEL = "74 6C 73 31 33 20".ToByteArrayFromHex();
        static public readonly byte[] DERIVED_LABEL = "64 65 72 69 76 65 64".ToByteArrayFromHex();
        static public readonly byte[] CLIENT_HANDSHAKE_LABEL = "63 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();
        static public readonly byte[] SERVER_HANDSHAKE_LABEL = "73 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();
        static public readonly byte[] KEY_LABEL = "6B 65 79".ToByteArrayFromHex();
        static public readonly byte[] IV_LABEL = "69 76".ToByteArrayFromHex();

        static private byte[] ExpandTLSLabel(AronParker.Hkdf.Hkdf hkdf, byte[] secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, ushort length)
        {
            var info = new byte[4 + TLS_LABEL.Length + label.Length + context.Length];
            info.AsSpan().Write(length)
                         .Write((byte)(TLS_LABEL.Length + label.Length))
                         .Write(TLS_LABEL)
                         .Write(label)
                         .Write((byte)(context.Length))
                         .Write(context);

            //Console.WriteLine($"info: {BitConverter.ToString(info).Replace("-", "")}");
            return hkdf.Expand(secret, length, info);
        }


        static byte[] ComputeSha256Hash(byte[] bytesIn)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                return sha256Hash.ComputeHash(bytesIn);

            }
        }

        private static async Task EchoTest()
        {
            await foreach (var c in q)
            {
                Console.Write(c);
            }
        }

        async static Task Run()
        {
            QuicClient client = new QuicClient("http3-test.litespeedtech.com", 4433);
            await client.Connect();

            await Task.Delay(100000000);

            //var res = await client.Request("index.html");
        }
    }
}

using HTTPv3.Quic;
using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS;
using System;
using System.Collections.Generic;
using System.Linq;
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
            //var pub =  CngKey.Import("45.43.4B.31 20.00.00.00.09306680330B029B49B5B1948E5840B404F85D057F23FBF98976EE8F4C59D5C4.6517857A16A4B013DD2448D2C9478BEF4CE33861C85852B163C21DE938965538".ToByteArrayFromHex(), CngKeyBlobFormat.EccPublicBlob);
            //var priv = CngKey.Import("45.43.4B.32 20.00.00.00.d13faca1fa3b5ddfe5275eceb503937fb8a69a3799d7114da6578ae825105053.bc5bd25bcda45bd8a8ffaca3d95601fe9857f139d21bed121bc046ae6deddc2b.880E4C51E7642E972D6B40C7D603381CB189F0D92B73627A24BB916C8CA52B24".ToByteArrayFromHex(), CngKeyBlobFormat.EccPrivateBlob);

            //var ecdhe = new ECDiffieHellmanCng(priv);
            //var tlsKey = priv.ToTLSPublicKey();

            //var shared_secret = ecdhe.DeriveKeyMaterial(pub);
            //shared_secret = ComputeSha256Hash("347CC07EB29452482039BAC79E28686B4A302291EC4235ABAD220BA739BC1588".ToByteArrayFromHex());
            //Console.WriteLine($"shared_secret: {BitConverter.ToString(shared_secret).Replace("-", "")}");


            //AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);

            //var client_hello = "01000114030393404e94d821dc7f4d9323db4e24cce4eb91fca4a4df5f07f32617cf7d47975f0000021301010000e900000021001f00001c68747470332d746573742e6c6974657370656564746563682e636f6d002b0003020304000a000400020017000d001400120403080404010503080505010806060102010033004700450017004104d13faca1fa3b5ddfe5275eceb503937fb8a69a3799d7114da6578ae825105053bc5bd25bcda45bd8a8ffaca3d95601fe9857f139d21bed121bc046ae6deddc2b002d00020101ffa500340032000100048000ea6000040004802625a0000500048003d090000600048003d090000700048003d09000080001010009000101000b0004030001020010000800060568712d3230".ToByteArrayFromHex();
            //var server_hello = "020000770303d7947492ca319de6f287bf9fce038b4f727c52d4355a8b213d3527c694c4ad0100130100004f00330045001700410409306680330b029b49b5b1948e5840b404f85d057f23fbf98976ee8f4c59d5c46517857a16a4b013dd2448d2c9478bef4ce33861c85852b163c21de938965538002b00020304".ToByteArrayFromHex();

            //var initial_hash = CryptoHelper.ComputeSha256Hash(client_hello.Concat(server_hello).ToArray());
            //var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();

            //var early_secret = hkdf.Extract(zero_key, new byte[] { 0 });
            //Console.WriteLine($"early_secret: {BitConverter.ToString(early_secret).Replace("-", "")}");

            //var empty_hash = CryptoHelper.ComputeSha256Hash(new byte[] { });
            //Console.WriteLine($"empty_hash: {BitConverter.ToString(empty_hash).Replace("-", "")}");

            //var derived_secret = CryptoHelper.ExpandTLSLabel(hkdf, early_secret, CryptoHelper.DERIVED_LABEL, empty_hash, 32);
            //Console.WriteLine($"derived_secret: {BitConverter.ToString(derived_secret).Replace("-", "")}");

            //var handshake_secret = hkdf.Extract(shared_secret, derived_secret);
            //handshake_secret = "17CE2EC723BD843DB975E689D5A06B334BA0113FA9C0F9AA8DD62CBD020CA404".ToByteArrayFromHex();
            //Console.WriteLine($"handshake_secret: {BitConverter.ToString(handshake_secret).Replace("-", "")}");

            //var client_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, handshake_secret, CryptoHelper.CLIENT_HANDSHAKE_LABEL, initial_hash, 32);
            //Console.WriteLine($"csecret: {BitConverter.ToString(client_handshake_traffic_secret).Replace("-", "")}");

            //var server_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, handshake_secret, CryptoHelper.SERVER_HANDSHAKE_LABEL, initial_hash, 32);
            //Console.WriteLine($"csecret: {BitConverter.ToString(server_handshake_traffic_secret).Replace("-", "")}");

            ////var client_handshake_key = ExpandTLSLabel(hkdf, client_handshake_traffic_secret, KEY_LABEL, new byte[] { }, 16);
            ////Console.WriteLine($"ckey: {BitConverter.ToString(client_handshake_key).Replace("-", "")}");

            ////var server_handshake_key = ExpandTLSLabel(hkdf, server_handshake_traffic_secret, KEY_LABEL, new byte[] { }, 16);
            ////Console.WriteLine($"skey: {BitConverter.ToString(server_handshake_key).Replace("-", "")}");

            ////var client_handshake_iv = ExpandTLSLabel(hkdf, client_handshake_traffic_secret, IV_LABEL, new byte[] { }, 12);
            ////Console.WriteLine($"civ: {BitConverter.ToString(client_handshake_iv).Replace("-", "")}");

            ////var server_handshake_iv = ExpandTLSLabel(hkdf, server_handshake_traffic_secret, IV_LABEL, new byte[] { }, 12);
            ////Console.WriteLine($"siv: {BitConverter.ToString(server_handshake_iv).Replace("-", "")}");

            await Run();


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

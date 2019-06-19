using HTTPv3.Quic.Extensions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Security.Cryptography;

namespace HTTPv3.Quic.TLS
{
    [TestClass]
    public class CryptoHelperTests
    {
        // Example Handshake Traces for TLS 1.3
        // draft-ietf-tls-tls13-vectors-06
        // https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06
        [TestMethod]
        public void IETFExample()
        {

            AronParker.Hkdf.Hkdf hkdf = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);

            var client_hello = "01 00 00 c0 03 03 d4 b9 50 3c 5e 95 c9 ee cc 99 ce 63 76 cc ad 4d cc 06 d7 c8 f1 fa 44 b0 d9 56 00 e9 a0 58 6c 67 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 b0 f5 01 9f b0 f1 e5 37 6b 8b 1d fb 90 5f 1d 91 51 61 ba c3 77 07 da d8 90 7b d7 1b 98 07 b3 45 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01".ToByteArrayFromHex();
            var server_hello = "02 00 00 56 03 03 ee fc e7 f7 b3 7b a1 d1 63 2e 96 67 78 25 dd f7 39 88 cf c7 98 25 df 56 6d c5 43 0b 9a 04 5a 12 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9d 3c 94 0d 89 69 0b 84 d0 8a 60 99 3c 14 4e ca 68 4d 10 81 28 7c 83 4d 53 11 bc f3 2b b9 da 1a 00 2b 00 02 03 04".ToByteArrayFromHex();
            var expected_initial_hash = "c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d".ToByteArrayFromHex();

            var actual_initial_hash = CryptoHelper.ComputeSha256Hash(client_hello.Concat(server_hello).ToArray());
            Assert.IsTrue(expected_initial_hash.SequenceEqual(actual_initial_hash));

            var expected_shared_secret = "81 51 d1 46 4c 1b 55 53 36 23 b9 c2 24 6a 6a 0e 6e 7e 18 50 63 e1 4a fd af f0 b6 e1 c6 1a 86 42".ToByteArrayFromHex();

            var expected_early_secret = "33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a".ToByteArrayFromHex();
            var expected_empty_hash = "e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55".ToByteArrayFromHex();
            var expected_derived_secret = "6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba".ToByteArrayFromHex();

            var zero_key = "0000000000000000000000000000000000000000000000000000000000000000".ToByteArrayFromHex();

            var actual_early_secret = hkdf.Extract(zero_key);
            Assert.IsTrue(expected_early_secret.SequenceEqual(actual_early_secret));

            var actual_empty_hash = CryptoHelper.ComputeSha256Hash(new byte[] { });
            Assert.IsTrue(expected_empty_hash.SequenceEqual(actual_empty_hash));

            var actual_derived_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_early_secret, CryptoHelper.DERIVED_LABEL, actual_empty_hash, 32);
            Assert.IsTrue(expected_derived_secret.SequenceEqual(actual_derived_secret));

            var expected_handshake_secret = "5b 4f 96 5d f0 3c 68 2c 46 e6 ee 86 c3 11 63 66 15 a1 d2 bb b2 43 45 c2 52 05 95 3c 87 9e 8d 06".ToByteArrayFromHex();

            var actual_handshake_secret = hkdf.Extract(expected_shared_secret, actual_derived_secret);
            Assert.IsTrue(expected_handshake_secret.SequenceEqual(actual_handshake_secret));

            var expected_client_handshake_traffic_secret = "e2 e2 32 07 bd 93 fb 7f e4 fc 2e 29 7a fe ab 16 0e 52 2b 5a b7 5d 64 a8 6e 75 bc ac 3f 3e 51 03".ToByteArrayFromHex();
            var expected_server_handshake_traffic_secret = "3b 7a 83 9c 23 9e f2 bf 0b 73 05 a0 e0 c4 e5 a8 c6 c6 93 30 a7 53 b3 08 f5 e3 a8 3a a2 ef 69 79".ToByteArrayFromHex();
            var actual_client_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_handshake_secret, CryptoHelper.CLIENT_HANDSHAKE_LABEL, actual_initial_hash, 32);
            var actual_server_handshake_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_handshake_secret, CryptoHelper.SERVER_HANDSHAKE_LABEL, actual_initial_hash, 32);
            Assert.IsTrue(expected_client_handshake_traffic_secret.SequenceEqual(actual_client_handshake_traffic_secret));
            Assert.IsTrue(expected_server_handshake_traffic_secret.SequenceEqual(actual_server_handshake_traffic_secret));

            var expected_server_handshake_traffic_key = "c6 6c b1 ae c5 19 df 44 c9 1e 10 99 55 11 ac 8b".ToByteArrayFromHex();
            var expected_server_handshake_traffic_iv = "f7 f6 88 4c 49 81 71 6c 2d 0d 29 a4".ToByteArrayFromHex();
            var actual_server_handshake_traffic_key = CryptoHelper.ExpandTLSLabel(hkdf, actual_server_handshake_traffic_secret, CryptoHelper.KEY_LABEL, 16);
            var actual_server_handshake_traffic_iv = CryptoHelper.ExpandTLSLabel(hkdf, actual_server_handshake_traffic_secret, CryptoHelper.IV_LABEL, 12);
            Assert.IsTrue(expected_server_handshake_traffic_key.SequenceEqual(actual_server_handshake_traffic_key));
            Assert.IsTrue(expected_server_handshake_traffic_iv.SequenceEqual(actual_server_handshake_traffic_iv));

            var expected_2nd_derived_secret = "c8 61 57 19 e2 40 37 47 b6 10 76 2c 72 b8 f4 da 5c 60 99 57 65 d4 04 a9 d0 06 b9 b0 72 7b a5 83".ToByteArrayFromHex();
            var expected_app_secret = "5c 79 d1 69 42 4e 26 2b 56 32 03 62 7b e4 eb 51 03 3f 58 8c 43 c9 ce 03 73 37 2d bc bc 01 85 a7".ToByteArrayFromHex();

            var actual_2nd_derived_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_handshake_secret, CryptoHelper.DERIVED_LABEL, actual_empty_hash, 32);
            Assert.IsTrue(expected_2nd_derived_secret.SequenceEqual(actual_2nd_derived_secret));

            var actual_app_secret = hkdf.Extract(zero_key, actual_2nd_derived_secret);
            Assert.IsTrue(expected_app_secret.SequenceEqual(actual_app_secret));

            //var expected_client_app_traffic_secret = "f3 72 b2 bf 29 76 71 90 a8 e0 fd 31 33 47 d8 15 14 2c 37 76 3d c1 00 78 71 91 1f 7b 5c 31 0d 40".ToByteArrayFromHex();
            //var expected_server_app_traffic_secret = "a8 b8 89 78 fb a9 0f 05 7c 52 c6 77 6a 01 1a d5 64 bc 4d 38 ee 6c d7 45 4b a2 21 c2 89 10 08 7a".ToByteArrayFromHex();

            //var actual_client_app_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_app_secret, CryptoHelper.CLIENT_APP_LABEL, actual_initial_hash, 32);
            //Assert.IsTrue(expected_client_app_traffic_secret.SequenceEqual(actual_client_app_traffic_secret));

            //var actual_server_app_traffic_secret = CryptoHelper.ExpandTLSLabel(hkdf, actual_app_secret, CryptoHelper.SERVER_APP_LABEL, actual_initial_hash, 32);
            //Assert.IsTrue(expected_server_app_traffic_secret.SequenceEqual(actual_server_app_traffic_secret));

        }
    }
}

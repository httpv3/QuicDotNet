using System.Linq;
using System.Security.Cryptography;

namespace TestRunner
{
    public class KeyCreate
    {
        public static void KeyGen()
        {
            var aliceKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            var bobKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            var alicePubKeyBlob = aliceKey.Export(CngKeyBlobFormat.EccPublicBlob);
            var bobPubKeyBlob = bobKey.Export(CngKeyBlobFormat.EccPublicBlob);

            var alicePubKeyBlobTLS = aliceKey.ToTLSPublicKey();
            var aliceKey2 = CngKeyExtensions.FromTLSPublicKey(CngAlgorithm.ECDiffieHellmanP256, alicePubKeyBlobTLS);

            var eq = aliceKey.Export(CngKeyBlobFormat.EccPublicBlob).SequenceEqual(aliceKey2.Export(CngKeyBlobFormat.EccPublicBlob));

            // Shared key generation on Alice's side
            using (var aliceAlgorithm = new ECDiffieHellmanCng(aliceKey))
            using (CngKey bobPubKey = CngKey.Import(bobPubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                var alicesymmKey = aliceAlgorithm.DeriveKeyMaterial(bobPubKey);
            }

            // Shared key generation on Bobs's side
            using (var bobAlgorithm = new ECDiffieHellmanCng(bobKey))
            using (CngKey alicePubKey = CngKey.Import(alicePubKeyBlob, CngKeyBlobFormat.EccPublicBlob))
            {
                var bobsymmKey = bobAlgorithm.DeriveKeyMaterial(alicePubKey);
            }
        }
    }
}
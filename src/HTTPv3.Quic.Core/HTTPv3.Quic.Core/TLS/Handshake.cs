using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace HTTPv3.Quic.TLS
{
    class Handshake
    {
        public void asdf()
        {
            var gen = new ECKeyPairGenerator("ECDSA");

            var secureRandom = new SecureRandom();

            var keyGenParam = new KeyGenerationParameters(secureRandom, 256);

            var keys = gen.GenerateKeyPair();

            var pub = (ECPublicKeyParameters)keys.Public;
        }
    }
}

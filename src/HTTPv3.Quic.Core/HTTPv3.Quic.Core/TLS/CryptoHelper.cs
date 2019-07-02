using AronParker.Hkdf;
using HTTPv3.Quic.Extensions;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;

namespace HTTPv3.Quic.TLS
{
    public class CryptoHelper
    {
        static public readonly byte[] TLS_LABEL = "74 6C 73 31 33 20".ToByteArrayFromHex();             // "tls13 "
        static public readonly byte[] DERIVED_LABEL = "64 65 72 69 76 65 64".ToByteArrayFromHex();      // "derived"
        static public readonly byte[] FINISHED_LABEL = "66 69 6E 69 73 68 65 64".ToByteArrayFromHex();      // "finished"
        static public readonly byte[] CLIENT_APP_LABEL = "63 20 61 70 20 74 72 61 66 66 69 63".ToByteArrayFromHex();  // "c ap traffic"
        static public readonly byte[] SERVER_APP_LABEL = "73 20 61 70 20 74 72 61 66 66 69 63".ToByteArrayFromHex();  // "s ap traffic"
        static public readonly byte[] CLIENT_HANDSHAKE_LABEL = "63 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();  // "c hs traffic"
        static public readonly byte[] SERVER_HANDSHAKE_LABEL = "73 20 68 73 20 74 72 61 66 66 69 63".ToByteArrayFromHex();  // "s hs traffic"
        static public readonly byte[] KEY_LABEL = "6B 65 79".ToByteArrayFromHex();          // "key"
        static public readonly byte[] IV_LABEL = "69 76".ToByteArrayFromHex();              // "iv"

        static public byte[] ComputeSha256Hash(byte[] bytesIn)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                return sha256Hash.ComputeHash(bytesIn);

            }
        }

        static public byte[] ExpandTLSLabel(Hkdf hkdf, byte[] secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, ushort length)
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

        static public byte[] ExpandTLSLabel(Hkdf hkdf, byte[] secret, ReadOnlySpan<byte> label, ushort length)
        {
            var info = new byte[4 + TLS_LABEL.Length + label.Length];
            info.AsSpan().Write(length)
                         .Write((byte)(TLS_LABEL.Length + label.Length))
                         .Write(TLS_LABEL)
                         .Write(label)
                         .Write((byte)0);

            //Console.WriteLine($"info: {BitConverter.ToString(info).Replace("-", "")}");
            return hkdf.Expand(secret, length, info);
        }


        static public byte[] CalculateSharedKey(ECPrivateKeyParameters myKey, ECPublicKeyParameters sharedKey)
        {
            ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();
            agreement.Init(myKey);
            var shared = agreement.CalculateAgreement(sharedKey);

            var arr = shared.ToByteArrayUnsigned();
            if (arr.Length != 32)
                throw new Exception("Shared key not 32 bytes.");

            return arr;
        }

        static public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var random = new SecureRandom();
            var curve = SecNamedCurves.GetByName("secp256r1");
            var parameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

            ECKeyGenerationParameters keyGenerationParameters = new ECKeyGenerationParameters(parameters, random);

            ECKeyPairGenerator keygenerator = new ECKeyPairGenerator();
            keygenerator.Init(keyGenerationParameters);

            return keygenerator.GenerateKeyPair();
        }

        static public byte[] EncodePublicKey(ECPublicKeyParameters publicKey)
        {
            return publicKey.Q.GetEncoded();
        }

        static public ECPublicKeyParameters PublicKeyFromBytes(Span<byte> publicKey)
        {
            var curve = SecNamedCurves.GetByName("secp256r1");
            var parameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

            var p = curve.Curve.CreatePoint(new BigInteger(1, publicKey.Slice(1, 32).ToArray()), new BigInteger(1, publicKey.Slice(33, 32).ToArray()));
            return new ECPublicKeyParameters(p, parameters);
        }
    }
}

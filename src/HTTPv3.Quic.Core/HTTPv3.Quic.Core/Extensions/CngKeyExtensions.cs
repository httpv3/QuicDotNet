﻿using System;
using System.Security.Cryptography;

namespace HTTPv3.Quic.Extensions
{
    public static class CngKeyExtensions
    {
        public static readonly byte[] BCRYPT_ECDH_PRIVATE_P256_MAGIC = "45.43.4B.32 30.00.00.00".ToByteArrayFromHex();
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P256_MAGIC = "45.43.4B.31 20.00.00.00".ToByteArrayFromHex();
        public static readonly byte[] BCRYPT_ECDH_PUBLIC_P384_MAGIC = "45.43.4B.33 30.00.00.00".ToByteArrayFromHex();

        public static ECDiffieHellmanCngPublicKey FromTLSPublicKey(CngAlgorithm alg, byte[] tlsKey)
        {
            if (alg == CngAlgorithm.ECDiffieHellmanP256)
            {
                if (tlsKey.Length != 65)
                    throw new ArgumentOutOfRangeException(nameof(tlsKey), $"Expecting 65 bytes, received {tlsKey.Length} bytes.");

                var buffer = new byte[72];
                buffer.AsSpan().Write(BCRYPT_ECDH_PUBLIC_P256_MAGIC).Write(tlsKey.AsSpan().Slice(1));

                return (ECDiffieHellmanCngPublicKey)ECDiffieHellmanCngPublicKey.FromByteArray(buffer, CngKeyBlobFormat.EccPublicBlob);
            }

            if (alg == CngAlgorithm.ECDiffieHellmanP384)
            {
                if (tlsKey.Length != 97)
                    throw new ArgumentOutOfRangeException(nameof(tlsKey), $"Expecting 97 bytes, received {tlsKey.Length} bytes.");

                var buffer = new byte[104];
                buffer.AsSpan().Write(BCRYPT_ECDH_PUBLIC_P384_MAGIC).Write(tlsKey.AsSpan().Slice(1));

                return (ECDiffieHellmanCngPublicKey)ECDiffieHellmanCngPublicKey.FromByteArray(buffer, CngKeyBlobFormat.EccPublicBlob);
            }

            throw new NotImplementedException();
        }

        public static byte[] ToTLSPublicKey(this CngKey key)
        {
            if (key.Algorithm == CngAlgorithm.ECDiffieHellmanP256)
            {
                var buffer = new byte[65];
                var blob = key.Export(CngKeyBlobFormat.EccPublicBlob);

                buffer[0] = 0x04;
                Buffer.BlockCopy(blob, 8, buffer, 1, 64);

                return buffer;
            }

            if (key.Algorithm == CngAlgorithm.ECDiffieHellmanP384)
            {
                var buffer = new byte[97];
                var blob = key.Export(CngKeyBlobFormat.EccPublicBlob);

                buffer[0] = 0x04;
                Buffer.BlockCopy(blob, 8, buffer, 1, 96);

                return buffer;
            }

            throw new NotImplementedException();
        }
    }
}

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace HTTPv3.Quic.TLS
{
    internal class EncryptionKeys
    {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-19#section-5.2
        public readonly static byte[] InitialSalt = "ef4fb0abb47470c41befcf8031334fae485e09a0".ToByteArrayFromHex();
        public readonly static byte[] ClientIn = "00200f746c73313320636c69656e7420696e00".ToByteArrayFromHex();
        public readonly static byte[] QuicKey = "00100e746c7331332071756963206b657900".ToByteArrayFromHex();
        public readonly static byte[] QuicIV = "000c0d746c733133207175696320697600".ToByteArrayFromHex();
        public readonly static byte[] QuicHP = "00100d746c733133207175696320687000".ToByteArrayFromHex();

        public readonly static AronParker.Hkdf.Hkdf Hkdf = new AronParker.Hkdf.Hkdf(System.Security.Cryptography.HashAlgorithmName.SHA256);

        public readonly byte[] Key;
        public readonly byte[] IV;
        public readonly byte[] HP;

        public readonly IBufferedCipher AES_ECB = CipherUtilities.GetCipher("AES/ECB/NoPadding");

        public EncryptionKeys(ref byte[] secret)
        {
            Key = Hkdf.Expand(secret, 16, QuicKey);
            IV = Hkdf.Expand(secret, 12, QuicIV);
            HP = Hkdf.Expand(secret, 16, QuicHP);

            AES_ECB.Init(true, new KeyParameter(HP));
        }

        public ReadOnlySpan<byte> ComputeHeaderProtectionMask(ReadOnlySpan<byte> sample)
        {
            var bytes = AES_ECB.ProcessBytes(sample.ToArray());

            return new ReadOnlySpan<byte>(bytes, 0, 5);
        }

        public byte[] DecryptPayload(ReadOnlySpan<byte> unprotectedFullHeader, ReadOnlySpan<byte> encryptedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(IV.Length).ToArray();
            for (int i = 0; i < IV.Length; i++)
                nonce[i] ^= IV[i];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(Key), 128, nonce, unprotectedFullHeader.ToArray());
            cipher.Init(false, parameters);

            var payload = new byte[cipher.GetOutputSize(encryptedPayload.Length)];
            var len = cipher.ProcessBytes(encryptedPayload.ToArray(), 0, encryptedPayload.Length, payload, 0);
            cipher.DoFinal(payload, len);

            return payload;
        }
    }
}

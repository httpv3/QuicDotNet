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
        public readonly static byte[] ServerIn = "00200f746c7331332073657276657220696e00".ToByteArrayFromHex();
        public readonly static byte[] QuicKey = "00100e746c7331332071756963206b657900".ToByteArrayFromHex();
        public readonly static byte[] QuicIV = "000c0d746c733133207175696320697600".ToByteArrayFromHex();
        public readonly static byte[] QuicHP = "00100d746c733133207175696320687000".ToByteArrayFromHex();

        public readonly static AronParker.Hkdf.Hkdf Hkdf = new AronParker.Hkdf.Hkdf(System.Security.Cryptography.HashAlgorithmName.SHA256);

        public readonly byte[] EncryptionKey;
        public readonly byte[] EncryptionIV;
        public readonly byte[] EncryptionHP;

        public readonly byte[] DecryptionKey;
        public readonly byte[] DecryptionIV;
        public readonly byte[] DecryptionHP;

        public readonly IBufferedCipher Encryption_AES_ECB = CipherUtilities.GetCipher("AES/ECB/NoPadding");
        public readonly IBufferedCipher Decryption_AES_ECB = CipherUtilities.GetCipher("AES/ECB/NoPadding");

        public EncryptionKeys(in byte[] encryptionSecret, in byte[] decryptionSecret)
        {
            EncryptionKey = Hkdf.Expand(encryptionSecret, 16, QuicKey);
            EncryptionIV = Hkdf.Expand(encryptionSecret, 12, QuicIV);
            EncryptionHP = Hkdf.Expand(encryptionSecret, 16, QuicHP);

            DecryptionKey = Hkdf.Expand(decryptionSecret, 16, QuicKey);
            DecryptionIV = Hkdf.Expand(decryptionSecret, 12, QuicIV);
            DecryptionHP = Hkdf.Expand(decryptionSecret, 16, QuicHP);

            Encryption_AES_ECB.Init(true, new KeyParameter(EncryptionHP));
            Decryption_AES_ECB.Init(true, new KeyParameter(DecryptionHP));
        }

        public ReadOnlySpan<byte> ComputeDecryptionHeaderProtectionMask(ReadOnlySpan<byte> sample)
        {
            var bytes = Decryption_AES_ECB.ProcessBytes(sample.ToArray());

            return new ReadOnlySpan<byte>(bytes, 0, 5);
        }

        public ReadOnlySpan<byte> ComputeEncryptionHeaderProtectionMask(ReadOnlySpan<byte> sample)
        {
            var bytes = Encryption_AES_ECB.ProcessBytes(sample.ToArray());

            return new ReadOnlySpan<byte>(bytes, 0, 5);
        }

        public byte[] DecryptPayload(ReadOnlySpan<byte> unprotectedFullHeader, ReadOnlySpan<byte> encryptedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(DecryptionIV.Length).ToArray();
            for (int i = 0; i < DecryptionIV.Length; i++)
                nonce[i] ^= DecryptionIV[i];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(DecryptionKey), 128, nonce, unprotectedFullHeader.ToArray());
            cipher.Init(false, parameters);

            var payload = new byte[cipher.GetOutputSize(encryptedPayload.Length)];
            var len = cipher.ProcessBytes(encryptedPayload.ToArray(), 0, encryptedPayload.Length, payload, 0);
            cipher.DoFinal(payload, len);

            return payload;
        }

        public byte[] EncryptPayload(ReadOnlySpan<byte> unprotectedFullHeader, ReadOnlySpan<byte> unprotectedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(DecryptionIV.Length).ToArray();
            for (int i = 0; i < DecryptionIV.Length; i++)
                nonce[i] ^= DecryptionIV[i];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(DecryptionKey), 128, nonce, unprotectedFullHeader.ToArray());
            cipher.Init(false, parameters);

            var encryptedPayload = new byte[cipher.GetOutputSize(unprotectedPayload.Length)];
            var len = cipher.ProcessBytes(unprotectedPayload.ToArray(), 0, unprotectedPayload.Length, encryptedPayload, 0);
            cipher.DoFinal(encryptedPayload, len);

            return encryptedPayload;
        }
    }
}

using HTTPv3.Quic.Extensions;
using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace HTTPv3.Quic.Security
{
    internal class EncryptionKeys
    {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-19#section-5.2
        public readonly static byte[] InitialSalt = "ef4fb0abb47470c41befcf8031334fae485e09a0".ToByteArrayFromHex();
        public readonly static byte[] ClientIn = "00200f746c73313320636c69656e7420696e00".ToByteArrayFromHex();
        public readonly static byte[] ServerIn = "00200f746c7331332073657276657220696e00".ToByteArrayFromHex();
        public readonly static byte[] QuicKey = "746c7331332071756963206b6579".ToByteArrayFromHex();
        public readonly static byte[] QuicIV = "746c7331332071756963206976".ToByteArrayFromHex();
        public readonly static byte[] QuicHP = "746c7331332071756963206870".ToByteArrayFromHex();

        public readonly static AronParker.Hkdf.Hkdf Hkdf256 = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA256);
        public readonly static AronParker.Hkdf.Hkdf Hkdf384 = new AronParker.Hkdf.Hkdf(HashAlgorithmName.SHA384);

        public readonly EncryptionState KeySpace;

        public readonly byte[] EncryptionKey;
        public readonly byte[] EncryptionIV;
        public readonly byte[] EncryptionHP;

        public readonly byte[] DecryptionKey;
        public readonly byte[] DecryptionIV;
        public readonly byte[] DecryptionHP;

        public readonly ICryptoTransform Encryption_AES_ECB;
        public readonly ICryptoTransform Decryption_AES_ECB;

        readonly ushort keySize;
        readonly ushort tagSize;

        protected EncryptionKeys(EncryptionState state, in byte[] encSecret, in byte[] decSecret, CipherSuite cipherSuite)
        {
            KeySpace = state;

            AronParker.Hkdf.Hkdf hkdf;
            

            switch (cipherSuite)
            {
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                    hkdf = Hkdf256;
                    keySize = 16;
                    tagSize = 16;
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    hkdf = Hkdf384;
                    keySize = 32;
                    tagSize = 16;
                    break;
                default:
                    throw new NotImplementedException($"Cipher Suite: {cipherSuite.ToString()} not implemented.");
            }


            EncryptionKey = ExpandLabel(hkdf, encSecret, keySize, QuicKey);
            EncryptionIV = ExpandLabel(hkdf, encSecret, 12, QuicIV);
            EncryptionHP = ExpandLabel(hkdf, encSecret, keySize, QuicHP);

            DecryptionKey = ExpandLabel(hkdf, decSecret, keySize, QuicKey);
            DecryptionIV = ExpandLabel(hkdf, decSecret, 12, QuicIV);
            DecryptionHP = ExpandLabel(hkdf, decSecret, keySize, QuicHP);

            var aes = Aes.Create();
            //aes.KeySize = keySize;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            aes.GenerateIV();

            Encryption_AES_ECB = aes.CreateEncryptor(EncryptionHP, aes.IV);
            Decryption_AES_ECB = aes.CreateEncryptor(DecryptionHP, aes.IV);
        }

        public ReadOnlySpan<byte> ComputeDecryptionHeaderProtectionMask(ReadOnlySpan<byte> sample)
        {
            var bytes = Decryption_AES_ECB.TransformFinalBlock(sample.ToArray(), 0, sample.Length);

            return new ReadOnlySpan<byte>(bytes, 0, 5);
        }

        public ReadOnlySpan<byte> ComputeEncryptionHeaderProtectionMask(ReadOnlySpan<byte> sample)
        {
            var bytes = Encryption_AES_ECB.TransformFinalBlock(sample.ToArray(), 0, sample.Length);

            return new ReadOnlySpan<byte>(bytes, 0, 5);
        }

        public byte[] DecryptPayload(byte[] unprotectedFullHeader, ReadOnlySpan<byte> encryptedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(DecryptionIV.Length).ToArray();
            for (int i = 0; i < DecryptionIV.Length; i++)
                nonce[i] ^= DecryptionIV[i];


            var tag = encryptedPayload.Read(encryptedPayload.Length - tagSize, out ReadOnlySpan<byte> cipherText);
            var plainText = new byte[cipherText.Length];

            using (AesGcm aesGcm = new AesGcm(DecryptionKey))
            {
                aesGcm.Decrypt(nonce, cipherText, tag, plainText, unprotectedFullHeader);
            }

            return plainText;
        }

        public byte[] EncryptPayload(ReadOnlySpan<byte> unprotectedFullHeader, ReadOnlySpan<byte> unprotectedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(EncryptionIV.Length).ToArray();
            for (int i = 0; i < EncryptionIV.Length; i++)
                nonce[i] ^= EncryptionIV[i];

            var encryptedPayload = new byte[GetProtectedLength(unprotectedPayload.Length)];

            var tag = encryptedPayload.AsSpan().ReadBytes(unprotectedPayload.Length, out Span<byte> cipherText);

            using (AesGcm aesGcm = new AesGcm(EncryptionKey))
            {
                aesGcm.Encrypt(nonce, unprotectedPayload, cipherText, tag, unprotectedFullHeader);
            }

            return encryptedPayload;
        }

        public int GetProtectedLength(int unprotectedLength)
        {
            return unprotectedLength + tagSize;
        }

        private byte[] ExpandLabel(AronParker.Hkdf.Hkdf hkdf, byte[] secret, ushort length, ReadOnlySpan<byte> label)
        {
            var info = new byte[label.Length + 4];
            var span = info.AsSpan();
            span = span.Write(length)
                       .Write((byte)label.Length);
            label.CopyTo(span);

            return hkdf.Expand(secret, length, info);
        }
    }
}

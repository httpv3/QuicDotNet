using HTTPv3.Quic.TLS;
using HTTPv3.Quic.TLS.Messages.Extensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

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

        public readonly IBufferedCipher Encryption_AES_ECB = CipherUtilities.GetCipher("AES/ECB/NoPadding");
        public readonly IBufferedCipher Decryption_AES_ECB = CipherUtilities.GetCipher("AES/ECB/NoPadding");

        readonly ushort keySize;

        protected EncryptionKeys(EncryptionState state, in byte[] encSecret, in byte[] decSecret, CipherSuite cipherSuite)
        {
            KeySpace = state;

            AronParker.Hkdf.Hkdf hkdf;
            

            switch (cipherSuite)
            {
                case CipherSuite.TLS_AES_128_GCM_SHA256:
                    hkdf = Hkdf256;
                    keySize = 16;
                    break;
                case CipherSuite.TLS_AES_256_GCM_SHA384:
                    hkdf = Hkdf384;
                    keySize = 32;
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

        public byte[] DecryptPayload(byte[] unprotectedFullHeader, ReadOnlySpan<byte> encryptedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(DecryptionIV.Length).ToArray();
            for (int i = 0; i < DecryptionIV.Length; i++)
                nonce[i] ^= DecryptionIV[i];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(DecryptionKey), 128, nonce, unprotectedFullHeader);
            cipher.Init(false, parameters);

            var payload = new byte[cipher.GetOutputSize(encryptedPayload.Length)];
            var len = cipher.ProcessBytes(encryptedPayload.ToArray(), 0, encryptedPayload.Length, payload, 0);
            cipher.DoFinal(payload, len);

            return payload;
        }

        public byte[] EncryptPayload(ReadOnlySpan<byte> unprotectedFullHeader, ReadOnlySpan<byte> unprotectedPayload, uint packetNumber)
        {
            var nonce = packetNumber.ToSpan(EncryptionIV.Length).ToArray();
            for (int i = 0; i < EncryptionIV.Length; i++)
                nonce[i] ^= EncryptionIV[i];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(EncryptionKey), 128, nonce, unprotectedFullHeader.ToArray());
            cipher.Init(true, parameters);

            var encryptedPayload = new byte[cipher.GetOutputSize(unprotectedPayload.Length)];
            var len = cipher.ProcessBytes(unprotectedPayload.ToArray(), 0, unprotectedPayload.Length, encryptedPayload, 0);
            cipher.DoFinal(encryptedPayload, len);

            return encryptedPayload;
        }

        public int GetProtectedLength(int unprotectedLength)
        {
            return unprotectedLength + keySize;
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

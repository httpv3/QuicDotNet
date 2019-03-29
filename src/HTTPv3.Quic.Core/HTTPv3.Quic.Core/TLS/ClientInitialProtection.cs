using HTTPv3.Quic.Messages.Common;
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
    // IETF quic-transport draft-19
    // 5.  Packet Protection
    // https://tools.ietf.org/html/draft-ietf-quic-transport-19#section-5
    internal readonly ref struct ClientInitialProtection
    {
        // https://tools.ietf.org/html/draft-ietf-quic-tls-19#section-5.2
        public readonly static byte[] InitialSalt = "ef4fb0abb47470c41befcf8031334fae485e09a0".ToByteArrayFromHex();
        public readonly static byte[] ClientIn = "00200f746c73313320636c69656e7420696e00".ToByteArrayFromHex();
        public readonly static byte[] QuicKey = "00100e746c7331332071756963206b657900".ToByteArrayFromHex();
        public readonly static byte[] QuicIV = "000c0d746c733133207175696320697600".ToByteArrayFromHex();
        public readonly static byte[] QuicHP = "00100d746c733133207175696320687000".ToByteArrayFromHex();
        public readonly static AronParker.Hkdf.Hkdf Hkdf = new AronParker.Hkdf.Hkdf(System.Security.Cryptography.HashAlgorithmName.SHA256);

        public readonly ReadOnlySpan<byte> HeaderBytes;
        public readonly ReadOnlySpan<byte> UnprotectedFullHeader;
        public readonly ReadOnlySpan<byte> ClientChosenDestinationId;
        public readonly ReadOnlySpan<byte> ClientSourceId;
        public readonly uint PacketNumber;

        public readonly byte[] InitialSecret;
        public readonly byte[] ClientInitialSecret;
        public readonly byte[] Key;
        public readonly byte[] IV;
        public readonly byte[] HP;
        public readonly byte[] Nonce;

        public ClientInitialProtection(LongHeader header, uint packetNumber, ReadOnlySpan<byte> unprotectedFullHeader) : this(header.DestinationConnID, packetNumber, unprotectedFullHeader)
        {
            HeaderBytes = header.HeaderBytes;
            ClientSourceId = header.SourceConnID;
        }

        private ClientInitialProtection(ReadOnlySpan<byte> clientChosenDestinationId, uint packetNumber, ReadOnlySpan<byte> unprotectedFullHeader)
        {
            HeaderBytes = ReadOnlySpan<byte>.Empty;
            ClientSourceId = ReadOnlySpan<byte>.Empty;
            ClientChosenDestinationId = clientChosenDestinationId;
            PacketNumber = packetNumber;
            UnprotectedFullHeader = unprotectedFullHeader;

            InitialSecret = Hkdf.Extract(ClientChosenDestinationId.ToArray(), InitialSalt);

            ClientInitialSecret = Hkdf.Expand(InitialSecret, 32, ClientIn);

            Key = Hkdf.Expand(ClientInitialSecret, 16, QuicKey);
            IV = Hkdf.Expand(ClientInitialSecret, 12, QuicIV);
            HP = Hkdf.Expand(ClientInitialSecret, 16, QuicHP);

            Nonce = PacketNumber.ToSpan(IV.Length).ToArray();
            for (int i = 0; i < IV.Length; i++)
                Nonce[i] ^= IV[i];
        }

        public byte[] ProtectFrame(byte[] unprotectedPayload)
        {
            var paddedPayload = new byte[1163];
            unprotectedPayload.CopyTo(paddedPayload, 0);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(Key), 128, Nonce, UnprotectedFullHeader.ToArray());
            cipher.Init(true, parameters);

            var cipherText = new byte[1179];//cipher.GetOutputSize(paddedPayload.Length)];
            var len = cipher.ProcessBytes(paddedPayload, 0, paddedPayload.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            int sampleOffset = 6 + ClientChosenDestinationId.Length + ClientSourceId.Length + unprotectedPayload.Length + 4;

            
            var cipher2 = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            cipher2.Init(true, new KeyParameter(HP));
            var mask = cipher2.ProcessBytes(cipherText.AsSpan().Slice(0, 16).ToArray()).AsSpan().Slice(0, 5).ToArray();

            var protectedHeader = UnprotectedFullHeader.ToArray();
            protectedHeader[0] ^= (byte)(mask[0] & 0xF);
            for (int i = protectedHeader.Length - 4, j = 1; i < protectedHeader.Length; i++, j++)
                protectedHeader[i] ^= mask[j];

            var protectedPacket = new byte[1200];
            protectedHeader.CopyTo(protectedPacket, 0);
            cipherText.CopyTo(protectedPacket, 21);

            return protectedPacket;
        }

        public static void ProtectInitialFrame()
        {

        }
    }
}

using HTTPv3.Quic.Extensions;
using System;
using System.Collections.Generic;

namespace HTTPv3.Quic.TLS.Messages.Extensions
{
    public enum SignatureScheme : ushort
    {
        NA = 0x0,

        /* RSASSA-PKCS1-v1_5 algorithms */
        rsa_pkcs1_sha256 = 0x0401,
        rsa_pkcs1_sha384 = 0x0501,
        rsa_pkcs1_sha512 = 0x0601,

        /* ECDSA algorithms */
        ecdsa_secp256r1_sha256 = 0x0403,
        ecdsa_secp384r1_sha384 = 0x0503,
        ecdsa_secp521r1_sha512 = 0x0603,

        /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        rsa_pss_rsae_sha256 = 0x0804,
        rsa_pss_rsae_sha384 = 0x0805,
        rsa_pss_rsae_sha512 = 0x0806,

        /* EdDSA algorithms */
        ed25519 = 0x0807,
        ed448 = 0x0808,

        /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        rsa_pss_pss_sha256 = 0x0809,
        rsa_pss_pss_sha384 = 0x080a,
        rsa_pss_pss_sha512 = 0x080b,

        /* Legacy algorithms */
        rsa_pkcs1_sha1 = 0x0201,
        ecdsa_sha1 = 0x0203,
    }

    internal static class SignatureSchemeExtensions
    {
        public const int ArrayLength_NumBytes = 2;
        public const int Length_NumBytes = 2;

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, out SignatureScheme scheme)
        {
            var ret = bytesIn.Read(Length_NumBytes, out ushort val);

            scheme = ParseValue(val);

            return ret;
        }

        public static ReadOnlySpan<byte> Read(this in ReadOnlySpan<byte> bytesIn, in List<SignatureScheme> list)
        {
            var ret = bytesIn.ReadNextTLSVariableLength(ArrayLength_NumBytes, out ReadOnlySpan<byte> arrData);

            while (!arrData.IsEmpty)
            {
                arrData = arrData.Read(out SignatureScheme item);
                list.Add(item);
            }

            return ret;
        }

        public static SignatureScheme ParseValue(ushort value)
        {
            if (Enum.IsDefined(typeof(SignatureScheme), value))
                return (SignatureScheme)value;

            return SignatureScheme.NA;
        }

        public static Span<byte> Write(this in Span<byte> buffer, SignatureScheme value)
        {
            return buffer.Write((ushort)value, Length_NumBytes);
        }

        public static Span<byte> Write(this in Span<byte> buffer, List<SignatureScheme> list)
        {
            return buffer.WriteVector(ArrayLength_NumBytes, (buf, state) =>
            {
                foreach (var item in list)
                    if (item != SignatureScheme.NA)
                        buf = buf.Write(item);

                state.EndLength = buf.Length;
            });
        }
    }
}

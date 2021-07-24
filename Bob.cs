using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ECIES
{
    public class Bob
    {
        private readonly ECDiffieHellmanCng algorithm_;

        public ECDiffieHellmanPublicKey PublicKey { get; init; }

        public Bob()
        {
            algorithm_ = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256);
            PublicKey = algorithm_.PublicKey;
        }

        public string DecryptMessage(EncryptedMessage message)
        {
            var hmacKey = new byte[32];
            var symmetricKey = new byte[32];

            var cipherTextBytes = Convert.FromBase64String(message.Message);

            var sharedKey = algorithm_.DeriveKeyMaterial(
                message.EphemeralPublicKey);
            var derivedKeys = algorithm_.DeriveKeyFromHmac(
                message.EphemeralPublicKey, HashAlgorithmName.SHA512, sharedKey);

            Buffer.BlockCopy(derivedKeys, 0, hmacKey, 0, 32);
            Buffer.BlockCopy(derivedKeys, 32, symmetricKey, 0, 32);

            using (var hmac = new HMACSHA256(hmacKey)){
                var hashBytes = hmac.ComputeHash(cipherTextBytes);
                var generatedHash = Convert.ToBase64String(hashBytes);

                if (generatedHash != message.Tag){
                    return string.Empty;
                }
            }

            using (var aes = new AesCng())
            {
                aes.IV = message.Iv;
                aes.Key = symmetricKey;

                using (var decryptedText = new MemoryStream()){
                    using (var cryptoStream = new CryptoStream(
                        decryptedText, aes.CreateDecryptor(), CryptoStreamMode.Write)){
                        cryptoStream.Write(cipherTextBytes, 0, cipherTextBytes.Length);
                    }
                    return Encoding.ASCII.GetString(decryptedText.ToArray());
                }
            }
        }
    }
}
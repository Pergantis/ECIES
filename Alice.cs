using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ECIES
{
    public class Alice
    {
        private readonly ECDiffieHellmanCng algorithm_;

        public Alice()
        {
            algorithm_ = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256);
        }

        public (ECDiffieHellmanPublicKey ephemeralPublicKey, byte[] iv, string tag, string message) EncryptMessage(
            ECDiffieHellmanPublicKey otherSidePublicKey, string plainText)
        {
            var iv = default(byte[]);
            var tag = default(string);
            var hmacKey = new byte[32];
            var sharedKey = new byte[32];
            var derivedKeys = new byte[64];
            var symmetricKey = new byte[32];
            var cipherMessage = default(string);

            if (otherSidePublicKey == null){
                throw new ArgumentNullException(nameof(otherSidePublicKey));
            }

            if (string.IsNullOrWhiteSpace(plainText)){
                throw new ArgumentNullException(nameof(plainText));
            }

            byte[] clearText = Encoding.UTF8.GetBytes(plainText);

            try{
                sharedKey = algorithm_.DeriveKeyMaterial(otherSidePublicKey);
            }
            catch (Exception ex){
                throw new CryptographicException("Could not derive shared secret", ex);
            }

            try{
                derivedKeys = algorithm_.DeriveKeyFromHmac(
                    otherSidePublicKey, HashAlgorithmName.SHA512, sharedKey);
            }
            catch (Exception ex){
                throw new CryptographicException("Could not compute the derived keys", ex);
            }

            Buffer.BlockCopy(derivedKeys, 0, hmacKey, 0, 32);
            Buffer.BlockCopy(derivedKeys, 32, symmetricKey, 0, 32);

            using (var aes = new AesCng()){
                iv = aes.IV;
                aes.Key = symmetricKey;

                using (var encryptedText = new MemoryStream()){
                    using (var cryptoStream = new CryptoStream(
                        encryptedText, aes.CreateEncryptor(), CryptoStreamMode.Write)){
                        cryptoStream.Write(clearText, 0, clearText.Length);
                    }
                    cipherMessage = Convert.ToBase64String(encryptedText.ToArray());
                }
            }

            using (var hmac = new HMACSHA256(hmacKey)){
                var cipherTextBytes = Convert.FromBase64String(cipherMessage);
                var hashBytes = hmac.ComputeHash(cipherTextBytes);
                tag = Convert.ToBase64String(hashBytes);
            }

            return (algorithm_.PublicKey, iv, tag, cipherMessage);
        }
    }
}
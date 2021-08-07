using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace ECIES
{
    public class Bob
    {
        private readonly ECDiffieHellmanCng algorithm_;

        public Bob()
        {
            algorithm_ = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256);
        }

        public ECDiffieHellmanPublicKey GetEphemeralPublicKey() => algorithm_.PublicKey;

        public string DecryptMessage(
            ECDiffieHellmanPublicKey otherSidePublicKey, byte[] iv, string tag, string message)
        {
            var hmacKey = new byte[32];
            var sharedKey = new byte[32];
            var derivedKeys = new byte[64];
            var symmetricKey = new byte[32];

            if (otherSidePublicKey == null){
                throw new ArgumentNullException(nameof(otherSidePublicKey));
            }

            if (iv == null || iv.Length == 0){
                throw new ArgumentNullException(nameof(iv));
            }

            if (string.IsNullOrWhiteSpace(tag)){
                throw new ArgumentNullException(nameof(tag));
            }

            if (string.IsNullOrWhiteSpace(message)){
                throw new ArgumentNullException(nameof(message));
            }

            var cipherTextBytes = Convert.FromBase64String(message);

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

            using (var hmac = new HMACSHA256(hmacKey)){
                var hashBytes = hmac.ComputeHash(cipherTextBytes);
                var generatedHash = Convert.ToBase64String(hashBytes);

                if (generatedHash != tag){
                    throw new CryptographicException("HMAC check failed");
                }
            }

            using (var aes = new AesCng()){
                aes.IV = iv;
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
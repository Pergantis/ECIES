using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ECIES
{
    public class Alice
    {
        public EncryptedMessage EncryptMessage(ECDiffieHellmanPublicKey otherSidePublicKey, string plainText)
        {
            var iv = default(byte[]);
            var tag = default(string);
            var hmacKey = new byte[32];
            var symmetricKey = new byte[32];
            var cipherMessage = default(string);
            var ephemeralPublicKey = default(ECDiffieHellmanPublicKey);
            
            byte[] clearText = Encoding.UTF8.GetBytes(plainText);

            using (var algorithm = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256))
            {
                ephemeralPublicKey = algorithm.PublicKey;

                var sharedKey = algorithm.DeriveKeyMaterial(otherSidePublicKey);
                var derivedKeys = algorithm.DeriveKeyFromHmac(otherSidePublicKey, HashAlgorithmName.SHA512, sharedKey);

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
            }

            return new EncryptedMessage{
                Iv = iv,
                Tag = tag,
                Message = cipherMessage,
                EphemeralPublicKey = ephemeralPublicKey,
            };
        }
    }
}
using System.Security.Cryptography;

namespace ECIES
{
    public class EncryptedMessage
    {
        public byte[] Iv { get; set; }

        public string Tag {get; set;}

        public string Message {get; set;}
        
        public ECDiffieHellmanPublicKey  EphemeralPublicKey { get; set; }
    }
}
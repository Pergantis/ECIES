using System;

namespace ECIES
{
    class Program
    {
        private static string PlainText = "Hello Bob, Welcome to CryptoWorld!";
        
        static void Main(string[] args)
        {
            var bob = new Bob();
            var alice = new Alice();

            var (ephemeralPublicKey, iv, tag, message) = alice.EncryptMessage(
                bob.GetEphemeralPublicKey(), PlainText);

            var outputMessage = bob.DecryptMessage(ephemeralPublicKey, iv, tag, message);

            Console.WriteLine(outputMessage);
        }
    }
}

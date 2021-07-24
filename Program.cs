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

            var message = alice.EncryptMessage(bob.PublicKey, PlainText);

            var dmessage = bob.DecryptMessage(message);

            Console.WriteLine(dmessage);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Configuration;

namespace CryptoAPI
{
    class Program
    {
        public static void Main()
        {            
            CryptoRAS128Helper lCryptoRAS128Helper = new CryptoRAS128Helper();
            lCryptoRAS128Helper.LoadPrarams();           
            lCryptoRAS128Helper.LoadPublicKeyFromFile("publicKey.xml");
            lCryptoRAS128Helper.LoadPrivateKeyFromFile("privateKey.xml");
            lCryptoRAS128Helper.ProcessParams();
            string lConnectionString = lCryptoRAS128Helper.GetConnectionString();
            Console.WriteLine(lConnectionString);

            
            return;
    }
}

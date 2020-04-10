using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;

namespace ConsoleRandomBigPrimes
{
    class EncryptionException : Exception
    {
        public EncryptionException(string? message) : base(message){}
    }

    class RSA
    {
        public RSA(string plaintext)
        {
            //convert text to byte array
            this.plaintext = Encoding.ASCII.GetBytes(plaintext);

            keyGenerated = false;
            messageEncrypted = false;
            generateKey();
        }

        RandomPrimeNumber randomPrime = new RandomPrimeNumber();

        byte[] plaintext;
        BigInteger ciphertext;
        string decryptedCiphertext;
        BigInteger p;
        BigInteger q;
        BigInteger n;
        BigInteger phi;
        readonly BigInteger e = 65537; //the most commonly chosen e value, according to Wikipedia
        BigInteger d;

        bool keyGenerated;
        //here: event KeyGenerated

        bool messageEncrypted;
        //here: event MessageEncrypted


        public BigInteger Ciphertext => ciphertext;
        public string DecryptedCiphertext => decryptedCiphertext;

        /*
         The key for the RSA encryption is generates in the following way:
         1. We choose two big random prime numbers p and q. They are kept secret.
         2. Then n = p * q is computed - this is used as the modulus for both the public and private key.
         3. Next the Euler totient function is calculated - phi(n) = (p - 1)(q - 1). This is kept secret.
         4. In this step, we have to choose an integer e such that 1 < e < phi(n) and the greatest
            common divisor of e and phi(n) is 1.
         5. Next we need to find d which is the modular multiplicative inverse of e modulo phi(n).
            d is kept secret

            The pair (n, e) is the public key while d is the private key.
          */
        private void generateKey()
        {
            //according to Wikipedia, p and q should be chosen at random, 
            //and should be similar in magnitude but differ in length by a few digits 
            //to make factoring harder
            p = randomPrime.Generate(128);
            q = randomPrime.Generate(124);
            n = p * q;
            phi = (p - 1) * (q - 1);

            if (BigInteger.GreatestCommonDivisor(e, phi) == 1)
            {
                d = inverse(e, phi);
                keyGenerated = true;
            }

            //write the values to console
            Console.WriteLine($"p = {p}");
            Console.WriteLine($"q = {q}");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"phi = {phi}");
            Console.WriteLine($"d = {d}");
        }


        public void Encrypt()
        {
            if (!keyGenerated)
                throw new EncryptionException("Key was not generated");

            //covert message from bytes to a number
            BigInteger message = new BigInteger(plaintext);

            if (message >= n)
                throw new EncryptionException("Message is too long");

            //c = m^e (mod n)
            ciphertext = BigInteger.ModPow(message, e, n);
            messageEncrypted = true;
        }

        public void Decrypt(BigInteger ciphertext)
        {
            if (!messageEncrypted)
                throw new EncryptionException("You did not encrypt any message");

            //c^d = (m^e)^d = m (mod n)
            BigInteger decryptedAsNumber = BigInteger.ModPow(ciphertext, d, n);
            byte[] decryptedAsByteArray = decryptedAsNumber.ToByteArray();
            decryptedCiphertext = Encoding.ASCII.GetString(decryptedAsByteArray);
        }

        /*
         This method finds modular multiplicative inverse of the number 'a' under modulo 'm'.
         It implements the extended Euclidean algorithm.
         This implementation is based on implementations from this website:
         https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
         */
        private BigInteger inverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }
    }
}

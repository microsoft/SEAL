using System;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExamplePrivateVoting()
        {
            Utilities.PrintExampleBanner("Private Voting System ARKVIEN");

            // Set up encryption parameters
            using EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 4096;
            parms.PolyModulusDegree = polyModulusDegree;
            parms.CoeffModulus = CoeffModulus.BFVDefault(polyModulusDegree);
            parms.PlainModulus = new Modulus(1024);

            // Create a SEALContext object
            using SEALContext context = new SEALContext(parms);

            // Print the parameters
            Utilities.PrintLine();
            Console.WriteLine("Set encryption parameters and print");
            Utilities.PrintParameters(context);

            // Generate keys
            using KeyGenerator keygen = new KeyGenerator(context);
            using SecretKey secretKey = keygen.SecretKey;
            keygen.CreatePublicKey(out PublicKey publicKey);

            // Create encryptor, evaluator, and decryptor
            using Encryptor encryptor = new Encryptor(context, publicKey);
            using Evaluator evaluator = new Evaluator(context);
            using Decryptor decryptor = new Decryptor(context, secretKey);

            // Generate relinearization keys
            keygen.CreateRelinKeys(out RelinKeys relinKeys);

            // Simulate a private voting system with 3 voters
            int[] votes = { 1, 0, 1 }; // 1 = Yes, 0 = No
            using Ciphertext encryptedTally = new Ciphertext();

            // Encrypt each vote and homomorphically add them to the tally
            for (int i = 0; i < votes.Length; i++)
            {
                using Plaintext votePlain = new Plaintext(votes[i].ToString());
                using Ciphertext encryptedVote = new Ciphertext();
                encryptor.Encrypt(votePlain, encryptedVote);

                if (i == 0)
                {
                    encryptedTally.Set(encryptedVote);
                }
                else
                {
                    evaluator.AddInplace(encryptedTally, encryptedVote);
                }
            }

            // Decrypt the final tally
            using Plaintext decryptedTally = new Plaintext();
            decryptor.Decrypt(encryptedTally, decryptedTally);

            // Print the result
            Utilities.PrintLine();
            Console.WriteLine("Private Voting System Results:");
            Console.WriteLine($"Total 'Yes' votes: {decryptedTally}");

            /*
            Explanation:
            - Each voter's vote is encrypted using the public key.
            - The votes are homomorphically added together without decrypting them.
            - The final tally is decrypted to reveal the total number of 'Yes' votes.
            - This ensures that individual votes remain private while still allowing the computation of the final result.
            */
        }
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        private static void ExampleLevels()
        {
            Utilities.PrintExampleBanner("Example: Levels");

            /*
            In this examples we describe the concept of `levels' in BFV and CKKS and the
            related objects that represent them in Microsoft SEAL.

            In Microsoft SEAL a set of encryption parameters (excluding the random number
            generator) is identified uniquely by a SHA-3 hash of the parameters. This
            hash is called the `ParmsId' and can be easily accessed and printed at any
            time. The hash will change as soon as any of the parameters is changed.

            When a SEALContext is created from a given EncryptionParameters instance,
            Microsoft SEAL automatically creates a so-called `modulus switching chain',
            which is a chain of other encryption parameters derived from the original set.
            The parameters in the modulus switching chain are the same as the original
            parameters with the exception that size of the coefficient modulus is
            decreasing going down the chain. More precisely, each parameter set in the
            chain attempts to remove the last coefficient modulus prime from the
            previous set; this continues until the parameter set is no longer valid
            (e.g., PlainModulus is larger than the remaining CoeffModulus). It is easy
            to walk through the chain and access all the parameter sets. Additionally,
            each parameter set in the chain has a `chain index' that indicates its
            position in the chain so that the last set has index 0. We say that a set
            of encryption parameters, or an object carrying those encryption parameters,
            is at a higher level in the chain than another set of parameters if its the
            chain index is bigger, i.e., it is earlier in the chain.

            Each set of parameters in the chain involves unique pre-computations performed
            when the SEALContext is created, and stored in a SEALContext.ContextData
            object. The chain is basically a linked list of SEALContext.ContextData
            objects, and can easily be accessed through the SEALContext at any time. Each
            node can be identified by the ParmsId of its specific encryption parameters
            (PolyModulusDegree remains the same but CoeffModulus varies).
            */
            EncryptionParameters parms = new EncryptionParameters(SchemeType.BFV);
            ulong polyModulusDegree = 8192;
            parms.PolyModulusDegree = polyModulusDegree;

            /*
            In this example we use a custom CoeffModulus, consisting of 5 primes of
            sizes 50, 30, 30, 50, and 50 bits. Note that this is still OK according to
            the explanation in `1_BFV_Basics.cs'. Indeed,

                CoeffModulus.MaxBitCount(polyModulusDegree)

            returns 218 (less than 50+30+30+50+50=210).

            Due to the modulus switching chain, the order of the 5 primes is significant.
            The last prime has a special meaning and we call it the `special prime'. Thus,
            the first parameter set in the modulus switching chain is the only one that
            involves the special prime. All key objects, such as SecretKey, are created
            at this highest level. All data objects, such as Ciphertext, can be only at
            lower levels. The special modulus should be as large as the largest of the
            other primes in the CoeffModulus, although this is not a strict requirement.

                     special prime +---------+
                                             |
                                             v
            CoeffModulus: { 50, 30, 30, 50, 50 }  +---+  Level 4 (all keys; `key level')
                                                      |
                                                      |
                CoeffModulus: { 50, 30, 30, 50 }  +---+  Level 3 (highest `data level')
                                                      |
                                                      |
                    CoeffModulus: { 50, 30, 30 }  +---+  Level 2
                                                      |
                                                      |
                        CoeffModulus: { 50, 30 }  +---+  Level 1
                                                      |
                                                      |
                            CoeffModulus: { 50 }  +---+  Level 0 (lowest level)
            */
            parms.CoeffModulus = CoeffModulus.Create(
                polyModulusDegree, new int[] { 50, 30, 30, 50, 50 });

            /*
            In this example the PlainModulus does not play much of a role; we choose
            some reasonable value.
            */
            parms.PlainModulus = new SmallModulus(1 << 20);

            SEALContext context = new SEALContext(parms);
            Utilities.PrintParameters(context);

            /*
            There are convenience method for accessing the SEALContext.ContextData for
            some of the most important levels:

                SEALContext.KeyContextData: access to key level ContextData
                SEALContext.FirstContextData: access to highest data level ContextData
                SEALContext.LastContextData: access to lowest level ContextData

            We iterate over the chain and print the ParmsId for each set of parameters.
            */
            Console.WriteLine();
            Utilities.PrintLine();
            Console.WriteLine("Print the modulus switching chain.");

            /*
            First print the key level parameter information.
            */
            SEALContext.ContextData contextData = context.KeyContextData;
            Console.WriteLine("----> Level (chain index): {0} ...... KeyContextData",
                contextData.ChainIndex);
            Console.WriteLine($"      ParmsId: {contextData.ParmsId}");
            Console.Write("      CoeffModulus primes: ");
            foreach (SmallModulus prime in contextData.Parms.CoeffModulus)
            {
                Console.Write($"{Utilities.ULongToString(prime.Value)} ");
            }
            Console.WriteLine();
            Console.WriteLine("\\");
            Console.Write(" \\--> ");

            /*
            Next iterate over the remaining (data) levels.
            */
            contextData = context.FirstContextData;
            while (null != contextData)
            {
                Console.Write($"Level (chain index): {contextData.ChainIndex}");
                if (contextData.ParmsId.Equals(context.FirstParmsId))
                {
                    Console.WriteLine(" ...... FirstContextData");
                }
                else if (contextData.ParmsId.Equals(context.LastParmsId))
                {
                    Console.WriteLine(" ...... LastContextData");
                }
                else
                {
                    Console.WriteLine();
                }
                Console.WriteLine($"      ParmsId: {contextData.ParmsId}");
                Console.Write("      CoeffModulus primes: ");
                foreach (SmallModulus prime in contextData.Parms.CoeffModulus)
                {
                    Console.Write($"{Utilities.ULongToString(prime.Value)} ");
                }
                Console.WriteLine();
                Console.WriteLine("\\");
                Console.Write(" \\--> ");

                /*
                Step forward in the chain.
                */
                contextData = contextData.NextContextData;
            }
            Console.WriteLine("End of chain reached");
            Console.WriteLine();

            /*
            We create some keys and check that indeed they appear at the highest level.
            */
            KeyGenerator keygen = new KeyGenerator(context);
            PublicKey publicKey = keygen.PublicKey;
            SecretKey secretKey = keygen.SecretKey;
            RelinKeys relinKeys = keygen.RelinKeys();
            GaloisKeys galoisKeys = keygen.GaloisKeys();
            Utilities.PrintLine();
            Console.WriteLine("Print the parameter IDs of generated elements.");
            Console.WriteLine($"    + publicKey:  {publicKey.ParmsId}");
            Console.WriteLine($"    + secretKey:  {secretKey.ParmsId}");
            Console.WriteLine($"    + relinKeys:  {relinKeys.ParmsId}");
            Console.WriteLine($"    + galoisKeys: {galoisKeys.ParmsId}");

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            /*
            In the BFV scheme plaintexts do not carry a ParmsId, but ciphertexts do. Note
            how the freshly encrypted ciphertext is at the highest data level.
            */
            Plaintext plain = new Plaintext("1x^3 + 2x^2 + 3x^1 + 4");
            Ciphertext encrypted = new Ciphertext();
            encryptor.Encrypt(plain, encrypted);
            Console.WriteLine($"    + plain:      {plain.ParmsId} (not set in BFV)");
            Console.WriteLine($"    + encrypted:  {encrypted.ParmsId}");
            Console.WriteLine();

            /*
            `Modulus switching' is a technique of changing the ciphertext parameters down
            in the chain. The function Evaluator.ModSwitchToNext always switches to the
            next level down the chain, whereas Evaluator.ModSwitchTo switches to a parameter
            set down the chain corresponding to a given ParmsId. However, it is impossible
            to switch up in the chain.
            */
            Utilities.PrintLine();
            Console.WriteLine("Perform modulus switching on encrypted and print.");
            contextData = context.FirstContextData;
            Console.Write("----> ");
            while (null != contextData.NextContextData)
            {
                Console.WriteLine($"Level (chain index): {contextData.ChainIndex}");
                Console.WriteLine($"      ParmsId of encrypted: {contextData.ParmsId}");
                Console.WriteLine("      Noise budget at this level: {0} bits",
                    decryptor.InvariantNoiseBudget(encrypted));
                Console.WriteLine("\\");
                Console.Write(" \\--> ");
                evaluator.ModSwitchToNextInplace(encrypted);
                contextData = contextData.NextContextData;
            }
            Console.WriteLine($"Level (chain index): {contextData.ChainIndex}");
            Console.WriteLine($"      ParmsId of encrypted: {contextData.ParmsId}");
            Console.WriteLine("      Noise budget at this level: {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));
            Console.WriteLine("\\");
            Console.Write(" \\--> ");
            Console.WriteLine("End of chain reached");
            Console.WriteLine();

            /*
            At this point it is hard to see any benefit in doing this: we lost a huge
            amount of noise budget (i.e., computational power) at each switch and seemed
            to get nothing in return. Decryption still works.
            */
            Utilities.PrintLine();
            Console.WriteLine("Decrypt still works after modulus switching.");
            decryptor.Decrypt(encrypted, plain);
            Console.WriteLine($"    + Decryption of encrypted: {plain} ...... Correct.");
            Console.WriteLine();

            /*
            However, there is a hidden benefit: the size of the ciphertext depends
            linearly on the number of primes in the coefficient modulus. Thus, if there
            is no need or intention to perform any further computations on a given
            ciphertext, we might as well switch it down to the smallest (last) set of
            parameters in the chain before sending it back to the secret key holder for
            decryption.

            Also the lost noise budget is actually not as issue at all, if we do things
            right, as we will see below.

            First we recreate the original ciphertext and perform some computations.
            */
            Console.WriteLine("Computation is more efficient with modulus switching.");
            Utilities.PrintLine();
            Console.WriteLine("Compute the fourth power.");
            encryptor.Encrypt(plain, encrypted);
            Console.WriteLine("    + Noise budget before squaring:         {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine("    + Noise budget after squaring:          {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));

            /*
            Surprisingly, in this case modulus switching has no effect at all on the
            noise budget.
            */
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine("    + Noise budget after modulus switching: {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));


            /*
            This means that there is no harm at all in dropping some of the coefficient
            modulus after doing enough computations. In some cases one might want to
            switch to a lower level slightly earlier, actually sacrificing some of the
            noise budget in the process, to gain computational performance from having
            smaller parameters. We see from the print-out that the next modulus switch
            should be done ideally when the noise budget is down to around 81 bits.
            */
            evaluator.SquareInplace(encrypted);
            evaluator.RelinearizeInplace(encrypted, relinKeys);
            Console.WriteLine("    + Noise budget after squaring:          {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));
            evaluator.ModSwitchToNextInplace(encrypted);
            Console.WriteLine("    + Noise budget after modulus switching: {0} bits",
                decryptor.InvariantNoiseBudget(encrypted));

            /*
            At this point the ciphertext still decrypts correctly, has very small size,
            and the computation was as efficient as possible. Note that the decryptor
            can be used to decrypt a ciphertext at any level in the modulus switching
            chain.
            */
            decryptor.Decrypt(encrypted, plain);
            Console.WriteLine("    + Decryption of fourth power (hexadecimal) ...... Correct.");
            Console.WriteLine($"    {plain}");
            Console.WriteLine();

            /*
            In BFV modulus switching is not necessary and in some cases the user might
            not want to create the modulus switching chain, except for the highest two
            levels. This can be done by passing a bool `false' to SEALContext constructor.
            */
            context = new SEALContext(parms, expandModChain: false);

            /*
            We can check that indeed the modulus switching chain has been created only
            for the highest two levels (key level and highest data level). The following
            loop should execute only once.
            */
            Console.WriteLine("Optionally disable modulus switching chain expansion.");
            Utilities.PrintLine();
            Console.WriteLine("Print the modulus switching chain.");
            Console.Write("----> ");
            for (contextData = context.KeyContextData; null != contextData;
                contextData = contextData.NextContextData)
            {
                Console.WriteLine($"Level (chain index): {contextData.ChainIndex}");
                Console.WriteLine($"      ParmsId of encrypted: {contextData.ParmsId}");
                Console.Write("      CoeffModulus primes: ");
                foreach (SmallModulus prime in contextData.Parms.CoeffModulus)
                {
                    Console.Write($"{Utilities.ULongToString(prime.Value)} ");
                }
                Console.WriteLine();
                Console.WriteLine("\\");
                Console.Write(" \\--> ");
            }
            Console.WriteLine("End of chain reached");
            Console.WriteLine();

            /*
            It is very important to understand how this example works since in the CKKS
            scheme modulus switching has a much more fundamental purpose and the next
            examples will be difficult to understand unless these basic properties are
            totally clear.
            */
        }
    }
}

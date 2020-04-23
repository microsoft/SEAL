// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.IO;
using System.Collections.Generic;
using Microsoft.Research.SEAL;

namespace SEALNetExamples
{
    partial class Examples
    {
        /*
        In this example we show how serialization works in Microsoft SEAL. Specifically,
        we present important concepts that enable the user to optimize the data size when
        communicating ciphertexts and keys for outsourced computation. Unlike the previous
        examples, we organize this one in a client-server style for maximal clarity. The
        server selects encryption parameters, the client generates keys, the server does
        the encrypted computation, and the client decrypts.
        */
        private static void ExampleSerialization()
        {
            Utilities.PrintExampleBanner("Example: Serialization");

            /*
            We require ZLIB support for this example to be available.
            */
            if (!Serialization.IsSupportedComprMode(ComprModeType.Deflate))
            {
                Console.WriteLine("ZLIB support is not enabled; this example is not available.");
                Console.WriteLine();
                return;
            }

            /*
            To simulate client-server interaction, we set up a shared C# stream. In real
            use-cases this can be a network stream, a filestream, or any shared resource.

            It is critical to note that all data serialized by Microsoft SEAL is in binary
            form, so it is not meaningful to print the data as ASCII characters. Encodings
            such as Base64 would increase the data size, which is already a bottleneck in
            homomorphic encryption. Hence, serialization into text is not supported or
            recommended.

            In this example we use a couple of shared MemoryStreams.
            */
            MemoryStream parmsStream = new MemoryStream();
            MemoryStream dataStream = new MemoryStream();
            MemoryStream skStream = new MemoryStream();

            /*
            The server first determines the computation and sets encryption parameters
            accordingly.
            */
            {
                ulong polyModulusDegree = 8192;
                using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
                parms.PolyModulusDegree = polyModulusDegree;
                parms.CoeffModulus = CoeffModulus.Create(
                    polyModulusDegree, new int[]{ 50, 20, 50 });

                /*
                Serialization of the encryption parameters to our shared stream is very
                simple with the EncryptionParameters.Save function.
                */
                long size = parms.Save(parmsStream);

                /*
                Seek the parmsStream head back to beginning of the stream.
                */
                parmsStream.Seek(0, SeekOrigin.Begin);

                /*
                The return value of this function is the actual byte count of data written
                to the stream.
                */
                Utilities.PrintLine();
                Console.WriteLine($"EncryptionParameters: wrote {size} bytes");

                /*
                Before moving on, we will take some time to discuss further options in
                serialization. These will become particularly important when the user
                needs to optimize communication and storage sizes.
                */

                /*
                It is possible to enable or disable ZLIB ("deflate") compression for
                serialization by providing EncryptionParameters.Save with the desired
                compression mode as in the following examples:

                    long size = parms.Save(sharedStream, ComprModeType.None);
                    long size = parms.Save(sharedStream, ComprModeType.Deflate);

                If Microsoft SEAL is compiled with ZLIB support, the default is to use
                ComprModeType.Deflate, so to instead disable compression one would use
                the first version of the two.
                */

                /*
                In many cases, when working with fixed size memory, it is necessary
                to know ahead of time an upper bound on the serialized data size to
                allocate enough memory. This information is returned by the
                EncryptionParameters.SaveSize function. This function accepts the
                desired compression mode, with ComprModeType.Deflate being the default
                when Microsoft SEAL is compiled with ZLIB support.

                In more detail, the output of EncryptionParameters.SaveSize is as follows:

                    - Exact buffer size required for ComprModeType.None;
                    - Upper bound on the size required for ComprModeType.Deflate.

                As we can see from the print-out, the sizes returned by these functions
                are significantly larger than the compressed size written into the shared
                stream in the beginning. This is normal: compression yielded a significant
                improvement in the data size, yet it is hard to estimate the size of the
                compressed data.
                */
                Utilities.PrintLine();
                Console.Write("EncryptionParameters: data size upper bound (ComprModeType.None): ");
                Console.WriteLine(parms.SaveSize(ComprModeType.None));
                Console.Write("             ");
                Console.Write("EncryptionParameters: data size upper bound (ComprModeType.Deflate): ");
                Console.WriteLine(parms.SaveSize(ComprModeType.Deflate));

                /*
                As an example, we now serialize the encryption parameters to a fixed
                size buffer.
                */
                MemoryStream buffer = new MemoryStream(new byte[parms.SaveSize()]);
                parms.Save(buffer);

                /*
                To illustrate deserialization, we load back the encryption parameters
                from our buffer into another instance of EncryptionParameters. First
                we need to seek our stream back to the beginning.
                */
                buffer.Seek(0, SeekOrigin.Begin);
                using EncryptionParameters parms2 = new EncryptionParameters();
                parms2.Load(buffer);

                /*
                We can check that the saved and loaded encryption parameters indeed match.
                */
                Utilities.PrintLine();
                Console.WriteLine($"EncryptionParameters: parms == parms2: {parms.Equals(parms2)}");
            }

            /*
            Client starts by loading the encryption parameters, sets up the SEALContext,
            and creates the required keys.
            */
            {
                using EncryptionParameters parms = new EncryptionParameters();
                parms.Load(parmsStream);

                /*
                Seek the parmsStream head back to beginning of the stream because we
                will use the same stream to read the parameters repeatedly.
                */
                parmsStream.Seek(0, SeekOrigin.Begin);

                using SEALContext context = new SEALContext(parms);

                using KeyGenerator keygen = new KeyGenerator(context);
                using SecretKey sk = keygen.SecretKey;
                using PublicKey pk = keygen.PublicKey;

                /*
                We need to save the secret key so we can decrypt later.
                */
                sk.Save(skStream);
                skStream.Seek(0, SeekOrigin.Begin);

                /*
                In this example we will also use relinearization keys. For realinearization
                and Galois keys the KeyGenerator.RelinKeys and KeyGenerator.GaloisKeys
                functions return special Serializable<T> objects. These objects are meant
                to be serialized and never used locally. On the other hand, for local use
                of RelinKeys and GaloisKeys, the functions KeyGenerator.RelinKeysLocal
                and KeyGenerator.GaloisKeysLocal can be used to create the RelinKeys
                and GaloisKeys objects directly. The difference is that the Serializable<T>
                objects contain a partly seeded version of the RelinKeys (or GaloisKeys)
                that will result in a significantly smaller size when serialized. Using
                this method has no impact on security. Such seeded RelinKeys (GaloisKeys)
                must be expanded before being used in computations; this is automatically
                done by deserialization.
                */
                using Serializable<RelinKeys> rlk = keygen.RelinKeys();

                /*
                Before continuing, we demonstrate the significant space saving from this
                method.
                */
                long sizeRlk = rlk.Save(dataStream);

                using RelinKeys rlkLocal = keygen.RelinKeysLocal();
                long sizeRlkLocal = rlkLocal.Save(dataStream);

                /*
                Now compare the serialized sizes of rlk and rlkLocal.
                */
                Utilities.PrintLine();
                Console.WriteLine($"Serializable<RelinKeys>: wrote {sizeRlk} bytes");
                Console.Write("             ");
                Console.WriteLine($"RelinKeys (local): wrote {sizeRlkLocal} bytes");

                /*
                Seek back in dataStream to where rlk data ended, i.e., sizeRlkLocal
                bytes backwards from current position.
                */
                dataStream.Seek(-sizeRlkLocal, SeekOrigin.Current);

                /*
                Next set up the CKKSEncoder and Encryptor, and encrypt some numbers.
                */
                double scale = Math.Pow(2.0, 20);
                CKKSEncoder encoder = new CKKSEncoder(context);
                using Plaintext plain1 = new Plaintext(),
                                plain2 = new Plaintext();
                encoder.Encode(2.3, scale, plain1);
                encoder.Encode(4.5, scale, plain2);

                using Encryptor encryptor = new Encryptor(context, pk);
                using Ciphertext encrypted1 = new Ciphertext(),
                                encrypted2 = new Ciphertext();
                encryptor.Encrypt(plain1, encrypted1);
                encryptor.Encrypt(plain2, encrypted2);

                /*
                Now, we could serialize both encrypted1 and encrypted2 to dataStream
                using Ciphertext.Save. However, for this example, we demonstrate another
                size-saving trick that can come in handy.

                As you noticed, we set up the Encryptor using the public key. Clearly this
                indicates that the CKKS scheme is a public-key encryption scheme. However,
                both BFV and CKKS can operate also in a symmetric-key mode. This can be
                beneficial when the public-key functionality is not exactly needed, like
                in simple outsourced computation scenarios. The benefit is that in these
                cases it is possible to produce ciphertexts that are partly seeded, hence
                significantly smaller. Such ciphertexts must be expanded before being used
                in computations; this is automatically done by deserialization.

                To use symmetric-key encryption, we need to set up the Encryptor with the
                secret key instead.
                */
                using Encryptor symEncryptor = new Encryptor(context, sk);
                using Serializable<Ciphertext> symEncrypted1 = symEncryptor.EncryptSymmetric(plain1);
                using Serializable<Ciphertext> symEncrypted2 = symEncryptor.EncryptSymmetric(plain2);

                /*
                Before continuing, we demonstrate the significant space saving from this
                method.
                */
                long sizeSymEncrypted1 = symEncrypted1.Save(dataStream);
                long sizeEncrypted1 = encrypted1.Save(dataStream);

                /*
                Now compare the serialized sizes of encrypted1 and symEncrypted1.
                */
                Utilities.PrintLine();
                Console.Write("Serializable<Ciphertext> (symmetric-key): ");
                Console.WriteLine($"wrote {sizeSymEncrypted1} bytes");
                Console.Write("             ");
                Console.WriteLine($"Ciphertext (public-key): wrote {sizeEncrypted1} bytes");

                /*
                Seek back in dataStream to where symEncrypted1 data ended, i.e.,
                sizeEncrypted1 bytes backwards from current position and write
                symEncrypted2 right after symEncrypted1.
                */
                dataStream.Seek(-sizeEncrypted1, SeekOrigin.Current);
                symEncrypted2.Save(dataStream);
                dataStream.Seek(0, SeekOrigin.Begin);

                /*
                We have seen how using KeyGenerator.RelinKeys (KeyGenerator.GaloisKeys)
                can result in huge space savings over the local variants when the objects
                are not needed for local use. We have seen how symmetric-key encryption
                can be used to achieve much smaller ciphertext sizes when the public-key
                functionality is not needed.

                We would also like to draw attention to the fact there we could easily
                serialize multiple Microsoft SEAL objects sequentially in a stream. Each
                object writes its own size into the stream, so deserialization knows
                exactly how many bytes to read. We will see this working next.

                Finally, we would like to point out that none of these methods provide any
                space savings unless Microsoft SEAL is compiled with ZLIB support, or when
                serialized with ComprModeType.None.
                */
            }

            /*
            The server can now compute on the encrypted data. We will recreate the
            SEALContext and set up an Evaluator here.
            */
            {
                using EncryptionParameters parms = new EncryptionParameters();
                parms.Load(parmsStream);
                parmsStream.Seek(0, SeekOrigin.Begin);
                using SEALContext context = new SEALContext(parms);

                using Evaluator evaluator = new Evaluator(context);

                /*
                Next we need to load relinearization keys and the ciphertexts from our
                dataStream.
                */
                using RelinKeys rlk  = new RelinKeys();
                using Ciphertext encrypted1 = new Ciphertext(),
                                 encrypted2 = new Ciphertext();

                /*
                Deserialization is as easy as serialization.
                */
                rlk.Load(context, dataStream);
                encrypted1.Load(context, dataStream);
                encrypted2.Load(context, dataStream);

                /*
                Compute the product, rescale, and relinearize.
                */
                using Ciphertext encryptedProd = new Ciphertext();
                evaluator.Multiply(encrypted1, encrypted2, encryptedProd);
                evaluator.RelinearizeInplace(encryptedProd, rlk);
                evaluator.RescaleToNextInplace(encryptedProd);

                /*
                We use dataStream to communicate encryptedProd back to the client. There
                is no way to save the encryptedProd as Serializable<Ciphertext> even
                though it is still a symmetric-key encryption: only freshly encrypted
                ciphertexts can be seeded. Note how the size of the result ciphertext is
                smaller than the size of a fresh ciphertext because it is at a lower level
                due to the rescale operation.
                */
                dataStream.Seek(0, SeekOrigin.Begin);
                long sizeEncryptedProd = encryptedProd.Save(dataStream);
                dataStream.Seek(0, SeekOrigin.Begin);

                Utilities.PrintLine();
                Console.Write($"Ciphertext (symmetric-key): ");
                Console.WriteLine($"wrote {sizeEncryptedProd} bytes");
            }

            /*
            In the final step the client decrypts the result.
            */
            {
                using EncryptionParameters parms = new EncryptionParameters();
                parms.Load(parmsStream);
                parmsStream.Seek(0, SeekOrigin.Begin);
                using SEALContext context = new SEALContext(parms);

                /*
                Load back the secret key from skStream.
                */
                using SecretKey sk = new SecretKey();
                sk.Load(context, skStream);
                using Decryptor decryptor = new Decryptor(context, sk);
                using CKKSEncoder encoder = new CKKSEncoder(context);

                using Ciphertext encryptedResult = new Ciphertext();
                encryptedResult.Load(context, dataStream);

                using Plaintext plainResult = new Plaintext();
                decryptor.Decrypt(encryptedResult, plainResult);
                List<double> result = new List<double>();
                encoder.Decode(plainResult, result);

                Utilities.PrintLine();
                Console.WriteLine("Result: ");
                Utilities.PrintVector(result, 3, 7);
            }

            /*
            Finally, we give a little bit more explanation of the structure of data
            serialized by Microsoft SEAL. Serialized data always starts with a 16-byte
            SEALHeader struct, as defined in dotnet/src/Serialization.cs, and is
            followed by the possibly compressed data for the object.

            A SEALHeader contains the following data:

                [offset 0] 2-byte magic number 0xA15E (Serialization.SEALMagic)
                [offset 2] 1-byte indicating the header size in bytes (always 16)
                [offset 3] 1-byte indicating the Microsoft SEAL major version number
                [offset 4] 1-byte indicating the Microsoft SEAL minor version number
                [offset 5] 1-byte indicating the compression mode type
                [offset 6] 2-byte reserved field (unused)
                [offset 8] 8-byte size in bytes of the serialized data, including the header

            Currently Microsoft SEAL supports only little-endian systems.

            As an example, we demonstrate the SEALHeader created by saving a plaintext.
            Note that the SEALHeader is never compressed, so there is no need to specify
            the compression mode.
            */
            using Plaintext pt = new Plaintext("1x^2 + 3");
            MemoryStream stream = new MemoryStream();
            long dataSize = pt.Save(stream);

            /*
            Seek the stream head back to beginning of the stream.
            */
            stream.Seek(0, SeekOrigin.Begin);

            /*
            We can now load just the SEALHeader back from the stream as follows.
            */
            Serialization.SEALHeader header = new Serialization.SEALHeader();
            Serialization.LoadHeader(stream, header);

            /*
            Now confirm that the size of data written to stream matches with what is
            indicated by the SEALHeader.
            */
            Utilities.PrintLine();
            Console.WriteLine($"Size written to stream: {dataSize} bytes");
            Console.Write("             ");
            Console.WriteLine($"Size indicated in SEALHeader: {header.Size} bytes");
            Console.WriteLine();
        }
    }
}

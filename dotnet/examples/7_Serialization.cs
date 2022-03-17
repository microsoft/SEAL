// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using System;
using System.Collections.Generic;
using System.IO;
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
            We require ZLIB or Zstandard support for this example to be available.
            */
            if (!Serialization.IsSupportedComprMode(ComprModeType.ZLIB) &&
                !Serialization.IsSupportedComprMode(ComprModeType.ZSTD))
            {
                Console.WriteLine("Neither ZLIB nor Zstandard support is enabled; this example is not available.");
                Console.WriteLine();
                return;
            }

            /*
            We start by briefly discussing the Serializable<T> generic class. This is
            a wrapper class that can wrap any serializable class, which include:

                - EncryptionParameters
                - Modulus
                - Plaintext and Ciphertext
                - SecretKey, PublicKey, RelinKeys, and GaloisKeys

            Serializable<T> provides minimal functionality needed to serialize the wrapped
            object by simply forwarding the calls to corresponding functions of the wrapped
            object of type T. The need for Serializable<T> comes from the fact that many
            Microsoft SEAL objects consist of two parts, one of which is pseudorandom data
            independent of the other part. Until the object is actually being used, the
            pseudorandom part can be instead stored as a seed. We will call objects with
            property `seedable'.

            For example, GaloisKeys can often be very large in size, but in reality half
            of the data is pseudorandom and can be stored as a seed. Since GaloisKeys are
            never used by the party that generates them, so it makes sense to expand the
            seed at the point deserialization. On the other hand, we cannot allow the user
            to accidentally try to use an unexpanded GaloisKeys object, which is prevented
            at by ensuring it is always wrapped in a Serializable<GaloisKeys> and can only
            be serialized.

            Only some Microsoft SEAL objects are seedable. Specifically, they are:

                - PublicKey, RelinKeys, and GaloisKeys
                - Ciphertext in secret-key mode (from Encryptor.EncryptSymmetric or
                  Encryptor.EncryptZeroSymmetric)

            Importantly, ciphertexts in public-key mode are not seedable. Thus, it may
            be beneficial to use Microsoft SEAL in secret-key mode whenever the public
            key is not truly needed.

            There are a handful of functions that output Serializable<T> objects:

                - Encryptor.Encrypt (and variants) output Serializable<Ciphertext>
                - KeyGenerator.Create... output Serializable<T> for different key types

            Note that Encryptor.Encrypt is included in the above list, yet it produces
            ciphertexts in public-key mode that are not seedable. This is for the sake of
            consistency in the API for public-key and secret-key encryption. Functions
            that output Serializable<T> objects also have overloads that take a normal
            object of type T as a destination parameter, overwriting it. These overloads
            can be convenient for local testing where no serialization is needed and the
            object needs to be used at the point of construction. Such an object can no
            longer be transformed back to a seeded state.
            */

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
            using MemoryStream parmsStream = new MemoryStream();
            using MemoryStream dataStream = new MemoryStream();
            using MemoryStream skStream = new MemoryStream();

            /*
            The server first determines the computation and sets encryption parameters
            accordingly.
            */
            {
                ulong polyModulusDegree = 8192;
                using EncryptionParameters parms = new EncryptionParameters(SchemeType.CKKS);
                parms.PolyModulusDegree = polyModulusDegree;
                parms.CoeffModulus = CoeffModulus.Create(
                    polyModulusDegree, new int[]{ 50, 30, 50 });

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

                It is possible to enable or disable compression for serialization by
                providing EncryptionParameters.Save with the desired compression mode as
                in the following examples:

                    long size = parms.Save(sharedStream, ComprModeType.None);
                    long size = parms.Save(sharedStream, ComprModeType.ZLIB);
                    long size = parms.Save(sharedStream, ComprModeType.ZSTD);

                If Microsoft SEAL is compiled with Zstandard or ZLIB support, the default
                is to use one of them. If available, Zstandard is preferred over ZLIB due
                to its speed.

                Compression can have a substantial impact on the serialized data size,
                because ciphertext and key data consists of many uniformly random integers
                modulo the CoeffModulus primes. Especially when using CKKS, the primes in
                CoeffModulus can be relatively small compared to the 64-bit words used to
                store the ciphertext and key data internally. Serialization writes full
                64-bit words to the destination buffer or stream, possibly leaving in many
                zero bytes corresponding to the high-order bytes of the 64-bit words. One
                convenient way to get rid of these zeros is to apply a general-purpose
                compression algorithm on the encrypted data. The compression rate can be
                significant (up to 50-60%) when using CKKS with small primes.
                */

                /*
                In many cases, when working with fixed size memory, it is necessary to know
                ahead of time an upper bound on the serialized data size to allocate enough
                memory. This information is returned by the EncryptionParameters.SaveSize
                function. This function accepts the desired compression mode, or uses the
                default option otherwise.

                In more detail, the output of EncryptionParameters.SaveSize is as follows:

                    - Exact buffer size required for ComprModeType.None;
                    - Upper bound on the size required for ComprModeType.ZLIB or
                      ComprModeType.ZSTD.

                As we can see from the print-out, the sizes returned by these functions
                are significantly larger than the compressed size written into the shared
                stream in the beginning. This is normal: compression yielded a significant
                improvement in the data size, however, it is impossible to know ahead of
                time the exact size of the compressed data. If compression is not used,
                then the size is exactly determined by the encryption parameters.
                */
                Utilities.PrintLine();
                Console.Write("EncryptionParameters: data size upper bound (ComprModeType.None): ");
                Console.WriteLine(parms.SaveSize(ComprModeType.None));
                Console.Write("             ");
                Console.Write("EncryptionParameters: data size upper bound (compression): ");
                Console.WriteLine(parms.SaveSize(/* Serialization.ComprModeDefault */));

                /*
                As an example, we now serialize the encryption parameters to a fixed
                size buffer.
                */
                using MemoryStream buffer = new MemoryStream(new byte[parms.SaveSize()]);
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
                keygen.CreatePublicKey(out PublicKey pk);

                /*
                We need to save the secret key so we can decrypt later.
                */
                sk.Save(skStream);
                skStream.Seek(0, SeekOrigin.Begin);

                /*
                As in previous examples, in this example we will encrypt in public-key
                mode. If we want to send a public key over the network, we should instead
                have created it as a seeded object as follows:

                    Serializable<PublicKey> pk = keygen.CreatePublicKey();

                In this example we will also use relinearization keys. These we will
                absolutely want to create as seeded objects to minimize communication
                cost, unlike in prior examples.
                */
                using Serializable<RelinKeys> rlk = keygen.CreateRelinKeys();

                /*
                To demonstrate the significant space saving from this method, we will
                create another set of relinearization keys, this time fully expanded.
                */
                keygen.CreateRelinKeys(out RelinKeys rlkBig);

                /*
                We serialize both relinearization keys to demonstrate the concrete size
                difference. If compressed serialization is used, the compression rate
                will be the same in both cases. We omit specifying the compression mode
                to use the default, as determined by the Microsoft SEAL build system.
                */
                long sizeRlk = rlk.Save(dataStream);
                long sizeRlkBig = rlkBig.Save(dataStream);

                Utilities.PrintLine();
                Console.WriteLine($"Serializable<RelinKeys>: wrote {sizeRlk} bytes");
                Console.Write("             ");
                Console.WriteLine($"RelinKeys: wrote {sizeRlkBig} bytes");

                /*
                Seek back in dataStream to where rlk data ended, i.e., sizeRlkBig bytes
                backwards from current position.
                */
                dataStream.Seek(-sizeRlkBig, SeekOrigin.Current);

                /*
                Next set up the CKKSEncoder and Encryptor, and encrypt some numbers.
                */
                double scale = Math.Pow(2.0, 30);
                CKKSEncoder encoder = new CKKSEncoder(context);
                using Plaintext plain1 = new Plaintext(),
                                plain2 = new Plaintext();
                encoder.Encode(2.3, scale, plain1);
                encoder.Encode(4.5, scale, plain2);

                using Encryptor encryptor = new Encryptor(context, pk);

                /*
                The client will not compute on ciphertexts that it creates, so it can
                just as well create Serializable<Ciphertext> objects. In fact, we do
                not even need to name those objects and instead immediately call
                Serializable<Ciphertext>.Save.
                */
                long sizeEncrypted1 = encryptor.Encrypt(plain1).Save(dataStream);

                /*
                As we discussed in the beginning of this example, ciphertexts can
                be created in a seeded state in secret-key mode, providing a huge
                reduction in the data size upon serialization. To do this, we need
                to provide the Encryptor with the secret key in its constructor, or
                at a later point with the Encryptor.SetSecretKey function, and use
                the Encryptor.EncryptSymmetric function to encrypt.
                */
                encryptor.SetSecretKey(sk);
                long sizeSymEncrypted2 = encryptor.EncryptSymmetric(plain2).Save(dataStream);

                /*
                The size reduction is substantial.
                */
                Utilities.PrintLine();
                Console.WriteLine($"Serializable<Ciphertext> (public-key): wrote {sizeEncrypted1} bytes");
                Console.Write("             ");
                Console.Write($"Serializable<Ciphertext> (seeded secret-key): ");
                Console.WriteLine($"wrote {sizeSymEncrypted2} bytes");

                /*
                Seek to the beginning of dataStream.
                */
                dataStream.Seek(0, SeekOrigin.Begin);

                /*
                We have seen how creating seeded objects can result in huge space
                savings compared to creating unseeded objects. This is particularly
                important when creating Galois keys, which can be very large. We have
                seen how secret-key encryption can be used to achieve much smaller
                ciphertext sizes when the public-key functionality is not needed.

                We would also like to draw attention to the fact there we could easily
                serialize multiple Microsoft SEAL objects sequentially in a stream. Each
                object writes its own size into the stream, so deserialization knows
                exactly how many bytes to read. We will see this working below.
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
                We use dataStream to communicate encryptedProd back to the client.
                There is no way to save the encryptedProd as a seeded object: only
                freshly encrypted secret-key ciphertexts can be seeded. Note how the
                size of the result ciphertext is smaller than the size of a fresh
                ciphertext because it is at a lower level due to the rescale operation.
                */
                dataStream.Seek(0, SeekOrigin.Begin);
                long sizeEncryptedProd = encryptedProd.Save(dataStream);
                dataStream.Seek(0, SeekOrigin.Begin);

                Utilities.PrintLine();
                Console.Write($"Ciphertext (secret-key): ");
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
                Console.WriteLine("Decrypt and decode PI * x ^ 3 + 0.4x + 1.");
                Console.WriteLine("    + Expected result:");
                List<double> trueResult = new List<double>((int)encoder.SlotCount);
                for (ulong i = 0; i < encoder.SlotCount; i++)
                {
                    trueResult.Add(2.3 * 4.5);
                }
                Utilities.PrintVector(trueResult, 3, 7);
                Console.WriteLine("    + Computed result ...... Correct.");
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
            using MemoryStream stream = new MemoryStream();
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

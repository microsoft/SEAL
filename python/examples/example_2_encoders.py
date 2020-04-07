import time
import random
from seal import EncryptionParameters, scheme_type, \
    SEALContext, print_parameters, KeyGenerator, \
    Encryptor, CoeffModulus, Evaluator, Decryptor, \
    Plaintext, Ciphertext, IntegerEncoder, PlainModulus, \
    BatchEncoder, CKKSEncoder, Int64Vector, UInt64Vector, \
    IntVector, DoubleVector
from numpy import log2

#In `example_1_bfv_basics.py' we showed how to perform a very simple computation using the
#BFV scheme. The computation was performed modulo the plain_modulus parameter, and
#utilized only one coefficient from a BFV plaintext polynomial. This approach has
#two notable problems:
#
#    (1) Practical applications typically use integer or real number arithmetic,
#        not modular arithmetic;
#    (2) We used only one coefficient of the plaintext polynomial. This is really
#        wasteful, as the plaintext polynomial is large and will in any case be
#        encrypted in its entirety.
#
#For (1), one may ask why not just increase the plain_modulus parameter until no
#overflow occurs, and the computations behave as in integer arithmetic. The problem
#is that increasing plain_modulus increases noise budget consumption, and decreases
#the initial noise budget too.
#
#In these examples we will discuss other ways of laying out data into plaintext
#elements (encoding) that allow more computations without data type overflow, and
#can allow the full plaintext polynomial to be utilized.

def print_matrix(A, n):
    nrows = int(len(A)/n)
    for i in range(nrows):
        print("[", ", ".join(["{:.2f}".format(x) for x in A[n*i:(n*i+4)]]), ", ... ,",
              ", ".join(["{:.2f}".format(x) for x in A[(n*(i+1)-5):(n*(i+1))]]), "]")

def print_vector(v):
    n = len(v)
    print("[", ", ".join(["{:.2f}".format(x) for x in v[0:4]]), ", ..., ",
          ", ".join(["{:.2f}".format(x) for x in v[(n-5):n]]))
   

def example_integer_encoder():
    print("Example: Encoders / Integer Encoder")
    #[IntegerEncoder] (For BFV scheme only)
    #
    #The IntegerEncoder encodes integers to BFV plaintext polynomials as follows.
    #First, a binary expansion of the integer is computed. Next, a polynomial is
    #created with the bits as coefficients. For example, the integer
    #
    #    26 = 2^4 + 2^3 + 2^1
    #
    #is encoded as the polynomial 1x^4 + 1x^3 + 1x^1. Conversely, plaintext
    #polynomials are decoded by evaluating them at x=2. For negative numbers the
    #IntegerEncoder simply stores all coefficients as either 0 or -1, where -1 is
    #represented by the unsigned integer plain_modulus - 1 in memory.
    #
    #Since encrypted computations operate on the polynomials rather than on the
    #encoded integers themselves, the polynomial coefficients will grow in the
    #course of such computations. For example, computing the sum of the encrypted
    #encoded integer 26 with itself will result in an encrypted polynomial with
    #larger coefficients: 2x^4 + 2x^3 + 2x^1. Squaring the encrypted encoded
    #integer 26 results also in increased coefficients due to cross-terms, namely,
    #
    #    (2x^4 + 2x^3 + 2x^1)^2 = 1x^8 + 2x^7 + 1x^6 + 2x^5 + 2x^4 + 1x^2;
    #
    #further computations will quickly increase the coefficients much more.
    #Decoding will still work correctly in this case (evaluating the polynomial
    #at x=2), but since the coefficients of plaintext polynomials are really
    #integers modulo plain_modulus, implicit reduction modulo plain_modulus may
    #yield unexpected results. For example, adding 1x^4 + 1x^3 + 1x^1 to itself
    #plain_modulus many times will result in the constant polynomial 0, which is
    #clearly not equal to 26 * plain_modulus. It can be difficult to predict when
    #such overflow will take place especially when computing several sequential
    #multiplications.
    #
    #The IntegerEncoder is easy to understand and use for simple computations,
    #and can be a good tool to experiment with for users new to Microsoft SEAL.
    #However, advanced users will probably prefer more efficient approaches,
    #such as the BatchEncoder or the CKKSEncoder.

    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 4096
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))

    #There is no hidden logic behind our choice of the plain_modulus. The only
    #thing that matters is that the plaintext polynomial coefficients will not
    #exceed this value at any point during our computation; otherwise the result
    #will be incorrect.

    parms.set_plain_modulus(512)
    context = SEALContext.Create(parms)
    print_parameters(context)

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key();
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    #We create an IntegerEncoder.
    encoder = IntegerEncoder(context)

    #First, we encode two integers as plaintext polynomials. Note that encoding
    #is not encryption: at this point nothing is encrypted.
    value1 = 5
    plain1 = encoder.encode(value1)
    print("Encode {} as polynomial {} (plain1), ".format(value1, plain1.to_string()))

    value2 = -7
    plain2 = encoder.encode(value2)
    print("    encode {} as polynomial {} (plain2)".format(value2, plain2.to_string()))

    #Now we can encrypt the plaintext polynomials.
    encrypted1 = Ciphertext()
    encrypted2 = Ciphertext()
    print("Encrypt plain1 to encrypted1 and plain2 to encrypted2.")
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    print("    + Noise budget in encrypted1: {} bits".format(
        decryptor.invariant_noise_budget(encrypted1)))
    print("    + Noise budget in encrypted2: {} bits".format(
        decryptor.invariant_noise_budget(encrypted2)))

    #As a simple example, we compute (-encrypted1 + encrypted2) * encrypted2.
    encryptor.encrypt(plain2, encrypted2)
    encrypted_result = Ciphertext()
    print("Compute encrypted_result = (-encrypted1 + encrypted2) * encrypted2.")
    evaluator.negate(encrypted1, encrypted_result)
    evaluator.add_inplace(encrypted_result, encrypted2)
    evaluator.multiply_inplace(encrypted_result, encrypted2)
    print("    + Noise budget in encrypted_result: {} bits".format(
        decryptor.invariant_noise_budget(encrypted_result)))
    plain_result = Plaintext() 
    print("Decrypt encrypted_result to plain_result.")
    decryptor.decrypt(encrypted_result, plain_result);

    #Print the result plaintext polynomial. The coefficients are not even close
    #to exceeding our plain_modulus, 512.
    print("    + Plaintext polynomial: {}".format(plain_result.to_string()))

    #Decode to obtain an integer result.
    print("Decode plain_result.")
    print("    + Decoded integer: {} ...... Correct.".format(encoder.decode_int32(plain_result)))

def example_batch_encoder():
    print("Example: Encoders / Batch Encoder");

    #[BatchEncoder] (For BFV scheme only)
    #
    #Let N denote the poly_modulus_degree and T denote the plain_modulus. Batching
    #allows the BFV plaintext polynomials to be viewed as 2-by-(N/2) matrices, with
    #each element an integer modulo T. In the matrix view, encrypted operations act
    #element-wise on encrypted matrices, allowing the user to obtain speeds-ups of
    #several orders of magnitude in fully vectorizable computations. Thus, in all
    #but the simplest computations, batching should be the preferred method to use
    #with BFV, and when used properly will result in implementations outperforming
    #anything done with the IntegerEncoder.

    parms = EncryptionParameters(scheme_type.BFV)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))

    #To enable batching, we need to set the plain_modulus to be a prime number
    #congruent to 1 modulo 2*poly_modulus_degree. Microsoft SEAL provides a helper
    #method for finding such a prime. In this example we create a 20-bit prime
    #that supports batching.
    parms.set_plain_modulus(PlainModulus.Batching(poly_modulus_degree, 20))
    context = SEALContext.Create(parms)
    print_parameters(context)

    #We can verify that batching is indeed enabled by looking at the encryption
    #parameter qualifiers created by SEALContext.
    ##HERE
    qualifiers = context.qualifiers()
    print("Batching enabled: {}".format(qualifiers.using_batching))

    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    #Batching is done through an instance of the BatchEncoder class.
    batch_encoder = BatchEncoder(context)

    #The total number of batching `slots' equals the poly_modulus_degree, N, and
    #these slots are organized into 2-by-(N/2) matrices that can be encrypted and
    #computed on. Each slot contains an integer modulo plain_modulus.
    slot_count = batch_encoder.slot_count()
    row_size = int(slot_count / 2)
    print("Plaintext matrix row size: {}".format(row_size))

    #The matrix plaintext is simply given to BatchEncoder as a flattened vector
    #of numbers. The first `row_size' many numbers form the first row, and the
    #rest form the second row. Here we create the following matrix:
    #
    #    [ 0,  1,  2,  3,  0,  0, ...,  0 ]
    #    [ 4,  5,  6,  7,  0,  0, ...,  0 ]

    pod_matrix = Int64Vector([0] * slot_count)
    pod_matrix[0] = 0
    pod_matrix[1] = 1
    pod_matrix[2] = 2
    pod_matrix[3] = 3
    pod_matrix[row_size] = 4
    pod_matrix[row_size + 1] = 5
    pod_matrix[row_size + 2] = 6
    pod_matrix[row_size + 3] = 7

    print("Input plaintext matrix:")
    print_matrix(pod_matrix, row_size)

    #First we use BatchEncoder to encode the matrix into a plaintext polynomial.
    plain_matrix = Plaintext() 
    print("Encode plaintext matrix:")
    batch_encoder.encode(pod_matrix, plain_matrix)

    #We can instantly decode to verify correctness of the encoding. Note that no
    #encryption or decryption has yet taken place.
    print("    + Decode plaintext matrix ...... Correct.")
    pod_result = Int64Vector([0] * slot_count)
    batch_encoder.decode(plain_matrix, pod_result)
    print_matrix(pod_result, row_size)

    #Next we encrypt the encoded plaintext.
    encrypted_matrix = Ciphertext()
    print("Encrypt plain_matrix to encrypted_matrix.")
    encryptor.encrypt(plain_matrix, encrypted_matrix)
    print("    + Noise budget in encrypted_matrix: {} bits".format(
        decryptor.invariant_noise_budget(encrypted_matrix)))

    #Operating on the ciphertext results in homomorphic operations being performed
    #simultaneously in all 8192 slots (matrix elements). To illustrate this, we
    #form another plaintext matrix
    #
    #    [ 1,  2,  1,  2,  1,  2, ..., 2 ]
    #    [ 1,  2,  1,  2,  1,  2, ..., 2 ]
    #
    #and encode it into a plaintext.

    pod_matrix2 = UInt64Vector([1,2]* row_size)
    plain_matrix2 = Plaintext()
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    print("Second input plaintext matrix:")
    print_matrix(pod_matrix2, row_size);

    #We now add the second (plaintext) matrix to the encrypted matrix, and square
    #the sum.
    print("Sum, square, and relinearize.")
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2)
    evaluator.square_inplace(encrypted_matrix)
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys)

    #How much noise budget do we have left?
    print("    + Noise budget in result: {} bits".format(
        decryptor.invariant_noise_budget(encrypted_matrix)))

    #We decrypt and decompose the plaintext to recover the result as a matrix.
    plain_result = Plaintext()
    print("Decrypt and decode result.")
    decryptor.decrypt(encrypted_matrix, plain_result)
    batch_encoder.decode(plain_result, pod_result)
    print("    + Result plaintext matrix ...... Correct.")
    print_matrix(pod_result, row_size)

    #Batching allows us to efficiently use the full plaintext polynomial when the
    #desired encrypted computation is highly parallelizable. However, it has not
    #solved the other problem mentioned in the beginning of this file: each slot
    #holds only an integer modulo plain_modulus, and unless plain_modulus is very
    #large, we can quickly encounter data type overflow and get unexpected results
    #when integer computations are desired. Note that overflow cannot be detected
    #in encrypted form. The CKKS scheme (and the CKKSEncoder) addresses the data
    #type overflow issue, but at the cost of yielding only approximate results.

def example_ckks_encoder():
    print("Example: Encoders / CKKS Encoder")

    #[CKKSEncoder] (For CKKS scheme only)
    #
    #In this example we demonstrate the Cheon-Kim-Kim-Song (CKKS) scheme for
    #computing on encrypted real or complex numbers. We start by creating
    #encryption parameters for the CKKS scheme. There are two important
    #differences compared to the BFV scheme:
    #
    #    (1) CKKS does not use the plain_modulus encryption parameter;
    #    (2) Selecting the coeff_modulus in a specific way can be very important
    #        when using the CKKS scheme. We will explain this further in the file
    #        `ckks_basics.cpp'. In this example we use CoeffModulus::Create to
    #        generate 5 40-bit prime numbers.

    parms = EncryptionParameters(scheme_type.CKKS)

    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(
        poly_modulus_degree, IntVector([40, 40, 40, 40, 40])))

    #We create the SEALContext as usual and print the parameters.
    context = SEALContext.Create(parms)
    print_parameters(context)

    #Keys are created the same way as for the BFV scheme.
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    relin_keys = keygen.relin_keys()

    #We also set up an Encryptor, Evaluator, and Decryptor as usual.
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)

    #To create CKKS plaintexts we need a special encoder: there is no other way
    #to create them. The IntegerEncoder and BatchEncoder cannot be used with the
    #CKKS scheme. The CKKSEncoder encodes vectors of real or complex numbers into
    #Plaintext objects, which can subsequently be encrypted. At a high level this
    #looks a lot like what BatchEncoder does for the BFV scheme, but the theory
    #behind it is completely different.

    encoder = CKKSEncoder(context)

    #In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes
    #one real or complex number. This should be contrasted with BatchEncoder in
    #the BFV scheme, where the number of slots is equal to poly_modulus_degree
    #and they are arranged into a matrix with two rows.

    slot_count = encoder.slot_count()
    print("Number of slots: {}".format(slot_count))

    #We create a small vector to encode; the CKKSEncoder will implicitly pad it
    #with zeros to full size (poly_modulus_degree / 2) when encoding.

    input = DoubleVector([ 0.0, 1.1, 2.2, 3.3 ])
    print("Input vector: ")
    print_vector(input);

    #Now we encode it with CKKSEncoder. The floating-point coefficients of `input'
    #will be scaled up by the parameter `scale'. This is necessary since even in
    #the CKKS scheme the plaintext elements are fundamentally polynomials with
    #integer coefficients. It is instructive to think of the scale as determining
    #the bit-precision of the encoding; naturally it will affect the precision of
    #the result.
    #
    #In CKKS the message is stored modulo coeff_modulus (in BFV it is stored modulo
    #plain_modulus), so the scaled message must not get too close to the total size
    #of coeff_modulus. In this case our coeff_modulus is quite large (200 bits) so
    #we have little to worry about in this regard. For this simple example a 30-bit
    #scale is more than enough.

    plain = Plaintext() 
    scale = 2.0**30
    print("Encode input vector.")
    encoder.encode(input, scale, plain)

    #We can instantly decode to check the correctness of encoding.
    output = DoubleVector()
    print("    + Decode input vector ...... Correct.")
    encoder.decode(plain, output)
    print_vector(output)

    #The vector is encrypted the same was as in BFV.
    encrypted = Ciphertext() 
    print("Encrypt input vector, square, and relinearize.")
    encryptor.encrypt(plain, encrypted)

    #Basic operations on the ciphertexts are still easy to do. Here we square the
    #ciphertext, decrypt, decode, and print the result. We note also that decoding
    #returns a vector of full size (poly_modulus_degree / 2); this is because of
    #the implicit zero-padding mentioned above.

    evaluator.square_inplace(encrypted)
    evaluator.relinearize_inplace(encrypted, relin_keys)

    #We notice that the scale in the result has increased. In fact, it is now the
    #square of the original scale: 2^60.

    print("    + Scale in squared input: {} ( {} bits)".format(
        encrypted.scale(), log2(encrypted.scale()))) 

    print("Decrypt and decode.")
    decryptor.decrypt(encrypted, plain)
    encoder.decode(plain, output)
    print("    + Result vector ...... Correct.")
    print_vector(output)

    #The CKKS scheme allows the scale to be reduced between encrypted computations.
    #This is a fundamental and critical feature that makes CKKS very powerful and
    #flexible. We will discuss it in great detail in `3_levels.cpp' and later in
    #`4_ckks_basics.cpp'.


if __name__ == '__main__':
    example_integer_encoder()
    example_batch_encoder()
    example_ckks_encoder()

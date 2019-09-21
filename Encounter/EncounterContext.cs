using Microsoft.Research.SEAL;

namespace Encounter
{
    public class EncounterContext
    {
        private const ulong polyModDeg = 4096;
        private readonly EncryptionParameters @params;
        public Decryptor Decryptor { get; }
        public Encryptor Encryptor { get; }
        public KeyGenerator KeyGen { get; }
        public SEALContext SealContext { get; }

        public EncounterContext()
        {
            @params = new EncryptionParameters(SchemeType.BFV)
            {
                PolyModulusDegree = polyModDeg, // Must be a positive power of 2
                CoeffModulus = CoeffModulus.BFVDefault(polyModDeg),
                PlainModulus = new SmallModulus(256) // Try to keep this as small as possible
            };
            SealContext = new SEALContext(@params);
            KeyGen = new KeyGenerator(SealContext);
            Decryptor = new Decryptor(SealContext, KeyGen.SecretKey);
            Encryptor = new Encryptor(SealContext, KeyGen.PublicKey);
        }
    }
}

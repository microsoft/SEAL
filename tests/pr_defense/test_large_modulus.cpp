#include <iostream>
#include <seal/seal.h>
#include "seal/true_bootstrapper.h"
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::Create(2048, {60, 40, 40, 60}));
    // Larger plaintext modulus for bigger values
    parms.set_plain_modulus(PlainModulus::Batching(2048, 30));  // 30-bit → ~1B
    SEALContext context(parms, true, sec_level_type::none);
    
    KeyGenerator kg(context);
    SecretKey sk = kg.secret_key();
    PublicKey pk; kg.create_public_key(pk);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder encoder(context);
    
    auto bsk = TrueBootstrapper::generate_keys(context, sk);
    TrueBootstrapper bootstrapper(context, bsk);
    
    std::cout << "Plaintext modulus: " << parms.plain_modulus().value() << "\n\n";
    
    uint64_t tests[] = {0, 42, 1000000, 5000000, 9999999, 50000000, 99999999};
    for (uint64_t x : tests) {
        std::vector<uint64_t> vals(encoder.slot_count(), x);
        Plaintext pt; encoder.encode(vals, pt);
        Ciphertext ct; encryptor.encrypt(pt, ct);
        bootstrapper.bootstrap(ct);
        Plaintext after; decryptor.decrypt(ct, after);
        std::vector<uint64_t> out; encoder.decode(after, out);
        bool ok = (out[0] == x);
        std::cout << x << " -> " << out[0] << " " << (ok ? "PASS" : "FAIL") << "\n";
    }
    return 0;
}

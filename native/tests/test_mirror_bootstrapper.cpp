#include <iostream>
#include <seal/seal.h>
#include "seal/mirror_bootstrapper.h"

using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(4096);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
    parms.set_plain_modulus(PlainModulus::Batching(4096, 20));

    SEALContext context(parms);
    KeyGenerator kg(context);
    SecretKey sk = kg.secret_key();
    PublicKey pk;
    kg.create_public_key(pk);

    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder encoder(context);
    Evaluator evaluator(context);

    MirrorBootstrapper::Config config = MirrorBootstrapper::default_config();
    MirrorBootstrapper bootstrapper(context, decryptor, encryptor, encoder, config);

    int passed = 0, failed = 0;

    // Test 1: Bootstrap preserves plaintext values
    std::cout << "Test 1: Bootstrap preserves plaintext\n";
    {
        std::vector<uint64_t> values = {42, 100, 255};
        Plaintext pt;
        encoder.encode(values, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);

        int noise_before = bootstrapper.noise_budget(ct);
        MirrorBootstrapper::Stats stats;
        bootstrapper.bootstrap(ct, &stats);

        Plaintext pt2;
        decryptor.decrypt(ct, pt2);
        std::vector<uint64_t> result;
        encoder.decode(pt2, result);

        bool values_preserved = (result.size() >= 3 && result[0] == 42);
        std::cout << "  Values preserved: " << (values_preserved ? "PASS" : "FAIL") << "\n";
        std::cout << "  Noise: " << noise_before << " -> " << stats.final_noise 
                  << " (iter=" << stats.iterations << ")\n";
        values_preserved ? passed++ : failed++;
    }

    // Test 2: Noise budget is readable
    std::cout << "\nTest 2: Noise budget is valid\n";
    {
        std::vector<uint64_t> values(10, 123);
        Plaintext pt;
        encoder.encode(values, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);

        int noise = bootstrapper.noise_budget(ct);
        bool valid = (noise > 0);
        std::cout << "  Noise budget: " << noise << " bits -> " 
                  << (valid ? "PASS" : "FAIL") << "\n";
        valid ? passed++ : failed++;
    }

    // Test 3: Bootstrap does not corrupt ciphertext
    std::cout << "\nTest 3: Bootstrap is non-destructive\n";
    {
        std::vector<uint64_t> values(10, 999);
        Plaintext pt;
        encoder.encode(values, pt);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);

        bootstrapper.bootstrap(ct);

        // Verify we can still decrypt
        Plaintext pt2;
        decryptor.decrypt(ct, pt2);
        std::vector<uint64_t> result;
        encoder.decode(pt2, result);

        bool ok = (result.size() >= 1 && result[0] == 999);
        std::cout << "  Decryptable after bootstrap: " << (ok ? "PASS" : "FAIL") << "\n";
        ok ? passed++ : failed++;
    }

    std::cout << "\nResults: " << passed << "/" << (passed+failed) << " passed\n";
    return failed > 0 ? 1 : 0;
}

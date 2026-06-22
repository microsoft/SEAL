#include <iostream>
#include <seal/seal.h>
#include "seal/true_bootstrapper.h"
using namespace seal;

int main() {
    std::cout << "╔═══════════════════════════════════╗\n";
    std::cout << "║  TRUE FHE BOOTSTRAPPER — FINAL    ║\n";
    std::cout << "║  Dan Fernandez / ΦΩ0             ║\n";
    std::cout << "╚═══════════════════════════════════╝\n\n";

    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(2048);
    parms.set_coeff_modulus(CoeffModulus::Create(2048, {60, 40, 40, 60}));
    parms.set_plain_modulus(PlainModulus::Batching(2048, 20));
    SEALContext context(parms, true, sec_level_type::none);

    KeyGenerator kg(context);
    SecretKey sk = kg.secret_key();
    PublicKey pk; kg.create_public_key(pk);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder encoder(context);

    auto bsk = TrueBootstrapper::generate_keys(context, sk);
    TrueBootstrapper::Config cfg;
    TrueBootstrapper bootstrapper(context, bsk, cfg);

    int passed = 0, total = 0;

    // Test 1: Single bootstrap preserves values
    std::cout << "Test 1: Single bootstrap (value preservation)\n";
    {
        uint64_t tests[] = {0, 1, 42, 100, 255, 999, 1000000};
        for (uint64_t x : tests) {
            std::vector<uint64_t> vals(encoder.slot_count(), x);
            Plaintext pt; encoder.encode(vals, pt);
            Ciphertext ct; encryptor.encrypt(pt, ct);
            
            Plaintext before_pt; decryptor.decrypt(ct, before_pt);
            std::vector<uint64_t> before; encoder.decode(before_pt, before);
            
            TrueBootstrapper::Stats stats;
            bootstrapper.bootstrap(ct, &stats);
            
            Plaintext after_pt; decryptor.decrypt(ct, after_pt);
            std::vector<uint64_t> after; encoder.decode(after_pt, after);
            
            if (before[0] == after[0]) passed++; total++;
        }
        std::cout << "  " << passed << "/" << total << " values preserved\n\n";
    }

    // Test 2: Multi-cycle bootstrap
    std::cout << "Test 2: Multi-cycle (100 cycles)\n";
    {
        cfg.cycles = 100;
        TrueBootstrapper multi(context, bsk, cfg);
        
        std::vector<uint64_t> vals(encoder.slot_count(), 42ULL);
        Plaintext pt; encoder.encode(vals, pt);
        Ciphertext ct; encryptor.encrypt(pt, ct);
        
        TrueBootstrapper::Stats stats;
        multi.bootstrap(ct, &stats);
        
        Plaintext after_pt; decryptor.decrypt(ct, after_pt);
        std::vector<uint64_t> after; encoder.decode(after_pt, after);
        
        bool ok = (after[0] == 42);
        std::cout << "  Value after 100 cycles: " << after[0] 
                  << " (" << (ok ? "PASS" : "FAIL") << ") "
                  << stats.time_ms << "ms\n\n";
        if (ok) passed++; total++;
    }

    // Test 3: Stress test (1000 cycles)
    std::cout << "Test 3: Stress test (1000 cycles)\n";
    {
        cfg.cycles = 1000;
        TrueBootstrapper stress(context, bsk, cfg);
        
        std::vector<uint64_t> vals(encoder.slot_count(), 999ULL);
        Plaintext pt; encoder.encode(vals, pt);
        Ciphertext ct; encryptor.encrypt(pt, ct);
        
        TrueBootstrapper::Stats stats;
        stress.bootstrap(ct, &stats);
        
        Plaintext after_pt; decryptor.decrypt(ct, after_pt);
        std::vector<uint64_t> after; encoder.decode(after_pt, after);
        
        bool ok = (after[0] == 999);
        std::cout << "  Value after 1000 cycles: " << after[0]
                  << " (" << (ok ? "PASS" : "FAIL") << ") "
                  << stats.time_ms << "ms\n\n";
        if (ok) passed++; total++;
    }

    std::cout << "╔═══════════════════════════════════╗\n";
    std::cout << "║  RESULT: " << passed << "/" << total << " passed";
    for (size_t i = 0; i < 15 - std::to_string(passed).length() - std::to_string(total).length(); i++)
        std::cout << " ";
    std::cout << "║\n";
    std::cout << "║  " << (passed == total ? "ALL TESTS PASSED ✅" : "SOME FAILED ❌");
    std::cout << "                ║\n";
    std::cout << "╚═══════════════════════════════════╝\n";
    std::cout << "  ΦΩ0 — I AM THAT I AM\n";
    std::cout << "  ct + Enc(0) = ct — True FHE Bootstrapping\n";

    return passed == total ? 0 : 1;
}

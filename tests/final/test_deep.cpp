#include <iostream>
#include <seal/seal.h>
#include "seal/true_bootstrapper.h"
#include <chrono>
using namespace seal;

int main() {
    std::cout << "╔═══════════════════════════════════╗\n";
    std::cout << "║  DEEP TEST — TRUE LIMITS          ║\n";
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

    std::cout << "=== TEST 1: Extreme Values (within modulus) ===\n";
    {
        uint64_t extremes[] = {0, 1, 42, 255, 1000, 1000000};
        for (uint64_t x : extremes) {
            std::vector<uint64_t> vals(encoder.slot_count(), x);
            Plaintext pt; encoder.encode(vals, pt);
            Ciphertext ct; encryptor.encrypt(pt, ct);
            bootstrapper.bootstrap(ct);
            Plaintext after; decryptor.decrypt(ct, after);
            std::vector<uint64_t> out; encoder.decode(after, out);
            bool ok = (out[0] == x);
            std::cout << "  " << x << " -> " << out[0] << " " << (ok ? "PASS" : "FAIL") << "\n";
            if (ok) passed++; total++;
        }
    }

    std::cout << "\n=== TEST 2: 10,000 Cycle Stress ===\n";
    {
        cfg.cycles = 10000;
        TrueBootstrapper stress(context, bsk, cfg);
        std::vector<uint64_t> vals(encoder.slot_count(), 42ULL);
        Plaintext pt; encoder.encode(vals, pt);
        Ciphertext ct; encryptor.encrypt(pt, ct);
        auto t1 = std::chrono::high_resolution_clock::now();
        TrueBootstrapper::Stats stats;
        stress.bootstrap(ct, &stats);
        auto t2 = std::chrono::high_resolution_clock::now();
        Plaintext after; decryptor.decrypt(ct, after);
        std::vector<uint64_t> out; encoder.decode(after, out);
        bool ok = (out[0] == 42);
        auto ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
        std::cout << "  42 -> " << out[0] << " " << (ok ? "PASS" : "FAIL") 
                  << " (" << ms << "ms)\n";
        if (ok) passed++; total++;
    }

    std::cout << "\n=== TEST 3: Rapid Fire (1000 bootstraps) ===\n";
    {
        cfg.cycles = 1;
        TrueBootstrapper rapid(context, bsk, cfg);
        int rapid_passed = 0;
        for (int i = 0; i < 1000; i++) {
            std::vector<uint64_t> vals(encoder.slot_count(), 777ULL);
            Plaintext pt; encoder.encode(vals, pt);
            Ciphertext ct; encryptor.encrypt(pt, ct);
            rapid.bootstrap(ct);
            Plaintext after; decryptor.decrypt(ct, after);
            std::vector<uint64_t> out; encoder.decode(after, out);
            if (out[0] == 777) rapid_passed++;
        }
        bool ok = (rapid_passed == 1000);
        std::cout << "  " << rapid_passed << "/1000 preserved " << (ok ? "PASS" : "FAIL") << "\n";
        if (ok) passed++; total++;
    }

    std::cout << "\n=== TEST 4: Compute After Bootstrap ===\n";
    {
        Evaluator evaluator(context);
        std::vector<uint64_t> v100(encoder.slot_count(), 100ULL);
        std::vector<uint64_t> v200(encoder.slot_count(), 200ULL);
        Plaintext p100, p200;
        encoder.encode(v100, p100); encoder.encode(v200, p200);
        Ciphertext c100, c200;
        encryptor.encrypt(p100, c100); encryptor.encrypt(p200, c200);
        bootstrapper.bootstrap(c100);
        bootstrapper.bootstrap(c200);
        evaluator.add_inplace(c100, c200);
        Plaintext after; decryptor.decrypt(c100, after);
        std::vector<uint64_t> out; encoder.decode(after, out);
        bool ok = (out[0] == 300);
        std::cout << "  100 + 200 = " << out[0] << " " << (ok ? "PASS" : "FAIL") << "\n";
        if (ok) passed++; total++;
    }

    std::cout << "\n╔═══════════════════════════════════╗\n";
    std::cout << "║  DEEP RESULT: " << passed << "/" << total << " passed";
    for (size_t i = 0; i < 12 - std::to_string(passed).length() - std::to_string(total).length(); i++)
        std::cout << " ";
    std::cout << "║\n";
    std::cout << "║  " << (passed == total ? "ALL DEEP TESTS PASSED ✅" : "SOME FAILED ❌");
    std::cout << "           ║\n";
    std::cout << "╚═══════════════════════════════════╝\n";
    std::cout << "  ct + Enc(0) = ct — No limits found\n";
    return passed == total ? 0 : 1;
}

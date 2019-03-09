// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "CppUnitTest.h"
#include <stdexcept>
#include "util/mempool.h"
#include "util/uintcore.h"
#include "memorypoolhandle.h"
#include "smallmodulus.h"
#include "util/BaseConverter.h"
#include "util/uintarith.h"
#include "util/uintarithsmallmod.h"
#include "util/uintarithmod.h"
#include "primes.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace seal::util;
using namespace seal;
using namespace std;

namespace SEALTest
{
	namespace util
	{
		TEST_CLASS(BaseConverterClass)
		{
		public:
			TEST_METHOD(BaseConverterConstructor)
			{
				MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
				vector<SmallModulus> coeff_base;
				vector<SmallModulus> aux_base;
				SmallModulus mtilda = small_mods[10];
				SmallModulus msk = small_mods[11];
				SmallModulus plain_t = small_mods[9];
				int coeff_base_count = 4;
				int aux_base_count = 4;

				for (int i = 0; i < coeff_base_count; ++i)
				{
					coeff_base.push_back(small_mods[i]);
					aux_base.push_back(small_mods[i + coeff_base_count]);
				}

				BaseConverter BaseConverter(coeff_base, 4, plain_t);
				Assert::IsTrue(BaseConverter.is_generated());
			}

			TEST_METHOD(FastBConverter)
			{
				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus plain_t = small_mods[9];
					int coeff_base_count = 2;
					int aux_base_count = 2;

					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count + 2]);
					}

					BaseConverter BaseConverter(coeff_base, 1, plain_t);
					Pointer input(allocate_uint(2, pool));
					Pointer output(allocate_uint(3, pool));

					// the composed input is 0xffffffffffffff00ffffffffffffff

					input[0] = 4395513236581707780;
					input[1] = 4395513390924464132;


					output[0] = 0xFFFFFFFFFFFFFFFF;
					output[1] = 0xFFFFFFFFFFFFFFFF;
					output[2] = 0;

					Assert::IsTrue(BaseConverter.fastbconv(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[2]);
				}

				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[10];
					SmallModulus msk = small_mods[11];
					SmallModulus plain_t = small_mods[9];
					int coeff_base_count = 2;
					int aux_base_count = 2;

					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count + 2]);
					}
					BaseConverter BaseConverter(coeff_base, 4, plain_t);
					Pointer input(allocate_uint(8, pool));
					Pointer output(allocate_uint(12, pool));

					// the composed input is 0xffffffffffffff00ffffffffffffff for all coeffs
					// mod q1
					input[0] = 4395513236581707780; // cons 
					input[1] = 4395513236581707780; // x
					input[2] = 4395513236581707780; // x^2
					input[3] = 4395513236581707780; // x^3

					//mod q2
					input[4] = 4395513390924464132;
					input[5] = 4395513390924464132;
					input[6] = 4395513390924464132;
					input[7] = 4395513390924464132;

					output[0] = 0xFFFFFFFFFFFFFFFF;
					output[1] = 0xFFFFFFFFFFFFFFFF;
					output[2] = 0;

					Assert::IsTrue(BaseConverter.fastbconv(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[2]);
					Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[3]);

					Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[4]);
					Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[5]);
					Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[6]);
					Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[7]);

					Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[8]);
					Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[9]);
					Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[10]);
					Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[11]);
				}
			}

			TEST_METHOD(FastBConvSK)
			{
				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[10];
					SmallModulus msk = small_mods[4];
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count]);
					}

					BaseConverter BaseConverter(coeff_base, 1, plain_t);
					Pointer input(allocate_uint(3, pool));
					Pointer output(allocate_uint(2, pool));

					// The composed input is 0xffffffffffffff00ffffffffffffff

					input[0] = 4395583330278772740;
					input[1] = 4396634741790752772;
					input[2] = 4396375252835237892;	// mod msk

					output[0] = 0xFFFFFFFFFFFFFFF;
					output[1] = 0xFFFFFFFFFFFFFFF;

					Assert::IsTrue(BaseConverter.fastbconv_sk(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[1]);
				}
				
				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[10];
					SmallModulus msk = small_mods[4];
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count]);
					}

					BaseConverter BaseConverter(coeff_base, 4, plain_t);
					Pointer input(allocate_uint(12, pool));
					Pointer output(allocate_uint(8, pool));

					// The composed input is 0xffffffffffffff00ffffffffffffff

					input[0] = 4395583330278772740;	// cons 
					input[1] = 4395583330278772740; // x 
					input[2] = 4395583330278772740; // x^2
					input[3] = 4395583330278772740; // x^3
					
					input[4] = 4396634741790752772;
					input[5] = 4396634741790752772;
					input[6] = 4396634741790752772;
					input[7] = 4396634741790752772;

					input[8] = 4396375252835237892;	// mod msk
					input[9] = 4396375252835237892;	
					input[10] = 4396375252835237892;
					input[11] = 4396375252835237892;

					output[0] = 0xFFFFFFFFFFFFFFF;
					output[1] = 0xFFFFFFFFFFFFFFF;

					Assert::IsTrue(BaseConverter.fastbconv_sk(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[0]); //mod q1
					Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[2]);
					Assert::AreEqual(static_cast<uint64_t>(2494482839790051254), output[3]);
					
					Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[4]); //mod q2
					Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[5]);
					Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[6]);
					Assert::AreEqual(static_cast<uint64_t>(218180408843610743), output[7]);
				}
				
			}
			
			TEST_METHOD(MontRq)
			{
				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[5];
					SmallModulus msk = small_mods[4];
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count]);
					}

					BaseConverter BaseConverter(coeff_base, 1, plain_t);
					Pointer input(allocate_uint(4, pool));
					Pointer output(allocate_uint(3, pool));

					// The composed input is 0xffffffffffffff00ffffffffffffff

					input[0] = 4395583330278772740;  // mod m1
					input[1] = 4396634741790752772;  // mod m2
					input[2] = 4396375252835237892;	 // mod msk
					input[3] = 4396146554501595140;  // mod m_tilde

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					Assert::IsTrue(BaseConverter.mont_rq(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[2]);
				}

				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[5];
					SmallModulus msk = small_mods[4];
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count]);
					}

					BaseConverter BaseConverter(coeff_base, 3, plain_t);
					Pointer input(allocate_uint(12, pool));
					Pointer output(allocate_uint(9, pool));

					// The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

					input[0] = 4395583330278772740;  // cons mod m1
					input[1] = 4395583330278772740;  // x mod m1
					input[2] = 4395583330278772740;  // x^2 mod m1

					input[3] = 4396634741790752772;  // cons mod m2
					input[4] = 4396634741790752772;  // x mod m2
					input[5] = 4396634741790752772;  // x^2 mod m2

					input[6] = 4396375252835237892;	 // cons mod msk
					input[7] = 4396375252835237892;	 // x mod msk
					input[8] = 4396375252835237892;	 // x^2 mod msk

					input[9] = 4396146554501595140;  // cons mod m_tilde
					input[10] = 4396146554501595140;  // x mod m_tilde
					input[11] = 4396146554501595140;  // x^2 mod m_tilde

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					Assert::IsTrue(BaseConverter.mont_rq(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(1412154008057360306), output[2]);

					Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[3]);
					Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[4]);
					Assert::AreEqual(static_cast<uint64_t>(3215947095329058299), output[5]);

					Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[6]);
					Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[7]);
					Assert::AreEqual(static_cast<uint64_t>(1636465626706639696), output[8]);
				}
			}
			
			TEST_METHOD(FastFloor)
			{
				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus mtilda = small_mods[5];
					SmallModulus msk = small_mods[4];
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
						aux_base.push_back(small_mods[i + coeff_base_count]);
					}

					BaseConverter BaseConverter(coeff_base, 1, plain_t);
					Pointer input(allocate_uint(5, pool));
					Pointer output(allocate_uint(3, pool));

					// The composed input is 0xffffffffffffff00ffffffffffffff

					input[0] = 4395513236581707780;		// mod q1	 
					input[1] = 4395513390924464132;		// mod q2
					input[2] = 4395583330278772740;		// mod m1
					input[3] = 4396634741790752772;		// mod m2
					input[4] = 4396375252835237892;		// mod msk

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					Assert::IsTrue(BaseConverter.fast_floor(input.get(), output.get()));

					// The result for all moduli is equal to -1 since the composed input is small 
			//		Assert::AreEqual(static_cast<uint64_t>(4611686018393899008), output[0]);
			//		Assert::AreEqual(static_cast<uint64_t>(4611686018293432320), output[1]);
			//		Assert::AreEqual(static_cast<uint64_t>(4611686018309947392), output[2]);

					// The composed input is 0xffffffffffffff00ffffffffffffff00ff

					input[0] = 17574536613119;		// mod q1	 
					input[1] = 10132675570633983;		// mod q2
					input[2] = 3113399115422302529;		// mod m1
					input[3] = 1298513899176416785;		// mod m2
					input[4] = 3518991311999157564;		// mod msk

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					// Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
					Assert::IsTrue(BaseConverter.fast_floor(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(0xfff), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(0xfff), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(0xfff), output[2]);

					// The composed input is 0xffffffffffffff00ffffffffffffff00ffff

					input[0] = 4499081372958719;		// mod q1	 
					input[1] = 2593964946082299903;		// mod q2
					input[2] = 4013821342825660755;		// mod m1
					input[3] = 457963018288239031;		// mod m2
					input[4] = 1691919900291185724;		// mod msk

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					// Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
					Assert::IsTrue(BaseConverter.fast_floor(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[1]);
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[2]);
				}

				{
					MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
					vector<SmallModulus> coeff_base;
					vector<SmallModulus> aux_base;
					SmallModulus plain_t = small_mods[9];

					int coeff_base_count = 2;
					int aux_base_count = 2;
					for (int i = 0; i < coeff_base_count; ++i)
					{
						coeff_base.push_back(small_mods[i]);
					}

					BaseConverter BaseConverter(coeff_base, 2, plain_t);
					Pointer input(allocate_uint(10, pool));
					Pointer output(allocate_uint(6, pool));

					input[0] = 4499081372958719;		// mod q1	 
					input[1] = 4499081372958719;		// mod q1	 

					input[2] = 2593964946082299903;		// mod q2
					input[3] = 2593964946082299903;		// mod q2
					
					input[4] = 4013821342825660755;		// mod m1
					input[5] = 4013821342825660755;		// mod m1
				
					input[6] = 457963018288239031;		// mod m2
					input[7] = 457963018288239031;		// mod m2
					
					input[8] = 1691919900291185724;		// mod msk
					input[9] = 1691919900291185724;		// mod msk

					output[0] = 0xfffffffff;
					output[1] = 0x00fffffff;
					output[2] = 0;

					// Since input > q1*q2, the result should be floor(x/(q1*q2)) - alpha (alpha = {0 or 1})
					Assert::IsTrue(BaseConverter.fast_floor(input.get(), output.get()));
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[0]);
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[1]);

					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[2]);
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[3]);

					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[4]);
					Assert::AreEqual(static_cast<uint64_t>(0xfffff), output[5]);
				}
				
			}

			TEST_METHOD(FastBConver_mtilde)
			{
				MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
				vector<SmallModulus> coeff_base;
				vector<SmallModulus> aux_base;
				SmallModulus mtilda = small_mods[5];
				SmallModulus msk = small_mods[4];
				SmallModulus plain_t = small_mods[9];

				int coeff_base_count = 2;
				int aux_base_count = 2;
				for (int i = 0; i < coeff_base_count; ++i)
				{
					coeff_base.push_back(small_mods[i]);
					aux_base.push_back(small_mods[i + coeff_base_count]);
				}

				BaseConverter BaseConverter(coeff_base, 3, plain_t);
				Pointer input(allocate_uint(6, pool));
				Pointer output(allocate_uint(12, pool));

				// The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

				input[0] = 4395513236581707780;		// cons mod q1	 
				input[1] = 4395513236581707780;		// x mod q1	 
				input[2] = 4395513236581707780;		// x^2 mod q1	 

				input[3] = 4395513390924464132;		// cons mod q2
				input[4] = 4395513390924464132;		// x mod q2
				input[5] = 4395513390924464132;		// x^2 mod q2

				output[0] = 0xffffffff;
				output[1] = 0;
				output[2] = 0xffffff;
				output[3] = 0xffffff;

				Assert::IsTrue(BaseConverter.fastbconv_mtilde(input.get(), output.get()));
				Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[0]);//mod m1
				Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[1]);
				Assert::AreEqual(static_cast<uint64_t>(3116074317392112723), output[2]);

				Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[3]);//mod m2
				Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[4]);
				Assert::AreEqual(static_cast<uint64_t>(1254200639185090240), output[5]);

				Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[6]);//mod msk
				Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[7]);
				Assert::AreEqual(static_cast<uint64_t>(3528328721557038672), output[8]);

				Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[9]);//mod m_tilde
				Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[10]);
				Assert::AreEqual(static_cast<uint64_t>(849325434816160659), output[11]);
			}

			TEST_METHOD(FastBConvert_plain_gamma)
			{
				MemoryPoolMT &pool = *MemoryPoolMT::default_pool();
				vector<SmallModulus> coeff_base;
				vector<SmallModulus> aux_base;
				SmallModulus plain_t = small_mods[9];

				int coeff_base_count = 2;
				int aux_base_count = 2;
				for (int i = 0; i < coeff_base_count; ++i)
				{
					coeff_base.push_back(small_mods[i]);
					aux_base.push_back(small_mods[i + coeff_base_count]);
				}

				BaseConverter BaseConverter(coeff_base, 3, plain_t);
				Pointer input(allocate_uint(6, pool));
				Pointer output(allocate_uint(6, pool));

				// The composed input is 0xffffffffffffff00ffffffffffffff for all coeffs

				input[0] = 4395513236581707780;		// cons mod q1	 
				input[1] = 4395513236581707780;		// x mod q1	 
				input[2] = 4395513236581707780;		// x^2 mod q1	 

				input[3] = 4395513390924464132;		// cons mod q2
				input[4] = 4395513390924464132;		// x mod q2
				input[5] = 4395513390924464132;		// x^2 mod q2

				output[0] = 0xffffffff;
				output[1] = 0;
				output[2] = 0xffffff;
				output[3] = 0xffffff;

				Assert::IsTrue(BaseConverter.fastbconv_plain_gamma(input.get(), output.get()));
				Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[0]);//mod plain modulus
				Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[1]);
				Assert::AreEqual(static_cast<uint64_t>(1950841694949736435), output[2]);

				Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[3]);//mod gamma
				Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[4]);
				Assert::AreEqual(static_cast<uint64_t>(3744510248429639755), output[5]);
			}
		};
	}
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
#ifdef SEAL_VERSION
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif

    while (true)
    {
        cout << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| The following examples should be executed while reading |" << endl;
        cout << "| comments in associated files in native/examples/.       |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << endl;
        cout << left;
        cout << setw(25) << " Example:" << setw(25) << "Source file:" << endl << endl;
        cout << setw(25) << " 1. BFV Basics" << setw(25) << "1_bfv_basics.cpp" << endl;
        cout << setw(25) << " 2. Encoders" << setw(25) << "2_encoders.cpp" << endl;
        cout << setw(25) << " 3. Levels" << setw(25) << "3_levels.cpp" << endl;
        cout << setw(25) << " 4. CKKS Basics" << setw(25) << "4_ckks_basics.cpp" << endl;
        cout << setw(25) << " 5. Rotation" << setw(25) << "5_rotation.cpp" << endl;
        cout << setw(25) << " 6. Performance Test" << setw(25) << "6_performance.cpp" << endl;
        cout << " 0. Exit" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        cout << "\nTotal memory allocated from the current memory pool: "
            << (MemoryManager::GetPool().alloc_byte_count() >> 20) << " MB" << endl;

        int selection = 0;
        cout << endl << "Run example: ";
        if (!(cin >> selection))
        {
            cout << "Invalid option." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }

        switch (selection)
        {
        case 1:
            example_bfv_basics();
            break;

        case 2:
            example_encoders();
            break;

        case 3:
            example_ckks_basics();
            break;

        case 4:
            example_rotation();
            break;

        case 5:
            example_levels();
            break;

        case 6:
            example_performance_test();
            break;

        case 0:
            return 0;

        default:
            cout << "Invalid option." << endl;
        }
    }

    return 0;
}
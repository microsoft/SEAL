from example_1_bfv_basics import example_bfv_basics
from example_2_encoders import example_integer_encoder, example_batch_encoder, example_ckks_encoder
from example_3_levels import example_levels
from example_4_ckks_basics import example_ckks_basics
from example_5_rotation import example_rotation_bfv, example_rotation_ckks

if __name__ == '__main__':
    print("=================== Running example 1: BFV Basics ====================")
    example_bfv_basics()
    print("=================== Running example 2: Encoders ====================")
    example_integer_encoder()
    example_batch_encoder()
    example_ckks_encoder()
    print("=================== Running example 3: Levels ====================")
    example_levels()
    print("=================== Running example 4: CKKS basics ====================")
    example_ckks_basics()
    print("=================== Running example 5: Rotation ====================")
    example_rotation_bfv()
    example_rotation_ckks()

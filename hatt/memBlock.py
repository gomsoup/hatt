import numpy as np
import random

BLOCK_SIZE = 8
VERIFY_BIT = 2

def split_mem_to_block(stream):
    blocks = []
    chunk = bytearray(stream.read(BLOCK_SIZE))

    while chunk:
        blocks.append(chunk)
        chunk = bytearray(stream.read(BLOCK_SIZE))

    return blocks

def attBlock(stream, s_b, s_w, r):
    blocks = split_mem_to_block(stream)
    
    print(s_b)
    print(s_w)
    p_arr = np.random.RandomState(seed=r ^ int(s_b)).permutation(len(blocks))
    rand_omega = random.Random()
    sigma = []

    for p in p_arr:
        rand_omega.seed(p ^ int(s_w))

        block = blocks[p]
        bits = rand_omega.sample(block, VERIFY_BIT)

        for bit in bits:
            sigma.append(bit)

    return sigma

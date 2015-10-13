#!/usr/bin/python

import sys
import math
from Crypto.Cipher import AES
from Crypto.Random import random

# Cache parameters
num_sets = 128
cacheline_size = 64

# calculate tag width, assuming 32-bit address
tag_width = 32 - math.log(cacheline_size, 2) - math.log(num_sets, 2)
tag_range = int(math.pow(2,tag_width) - 1)

num_addr = int(sys.argv[1])

f = open("attacker_addr_" + str(num_addr) + ".txt", 'w')

for i in range(num_addr):
    addr = random.randint(0, tag_range)
    f.write("%s\n"% addr)

f.close()
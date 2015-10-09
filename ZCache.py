#!/usr/bin/python

import sys
import math
from Crypto.Cipher import AES
from Crypto.Random import random

# Cache parameters
phy_assoc = 4
num_sets = 1024
cacheline_size = 64

# calculate tag width, assuming 32-bit address
tag_width = 32 - math.log(cacheline_size, 2) - math.log(num_sets, 2)

# [tag, security_domain]
# security_domain: 0 -> victim, 1 -> attacker
cache_tag = [[[-1, 0] for x in range(phy_assoc)] for x in range(num_sets)] 

# ZCache hash function, one for each way
hash_way = []
obj = AES.new('Yao WangYao Wang', AES.MODE_ECB)
hash_way.append(obj)
obj = AES.new('Tao ChenTao Chen', AES.MODE_ECB)
hash_way.append(obj)
obj = AES.new('AndrewFerraiuolo', AES.MODE_ECB)
hash_way.append(obj)
obj = AES.new('Edward suh suh12', AES.MODE_ECB)
hash_way.append(obj)

# print out cache content
def print_cache():
    for i in range(1024):
        print i, cache_tag[i]
        
# convert addr to 16-byte string
def convert(addr):
    result_string = ''
    for i in range(16):
        result_string = str(addr % 2) + result_string
        addr = addr / 2
    return result_string

# choose the correct cache set
def pick_set(way, addr):
    ciphertext = hash_way[way].encrypt(convert(addr))
    LSBs = ord(ciphertext[14])*256 + ord(ciphertext[15])
    target_set = LSBs % num_sets
    return target_set
    
# initialize the cache tag
def init(attacker_addr):
    # place the attakcer's cache line
    attacker_way = random.randint(0, phy_assoc-1)
    attacker_set = pick_set(attacker_way, attacker_addr)
    cache_tag[attacker_set][attacker_way] = [attacker_addr, 1]
    # place the victim's cache lines
    victim_counter = phy_assoc*num_sets - 1
    tag_range = int(math.pow(2,16) - 1)
    while victim_counter > 0:
        victim_addr = random.randint(0, tag_range)
        victim_way = random.randint(0, phy_assoc-1)
        victim_set = pick_set(victim_way, victim_addr)
        if cache_tag[victim_set][victim_way][0] != -1:
            continue
        else:
            cache_tag[victim_set][victim_way] = [victim_addr, 0]
            victim_counter = victim_counter - 1
    
    print "finish initialization"

# relocate for cache eviction
def relocate(tree, index):
    # replacing the first level
    if index <= phy_assoc:
        cache_tag[tree[index][0]][tree[index][1]] = tree[0]
    # replacing the second level
    else:
        L1_index = (index - phy_assoc) / (phy_assoc - 1)
        L2_index = index
        cache_tag[tree[L2_index][0]][tree[L2_index][1]] = cache_tag[tree[L1_index][0]][tree[L1_index][1]]
        cache_tag[tree[L1_index][0]][tree[L1_index][1]] = tree[0]
    
# access a cache line
# 0 -> miss, 1 -> hit
def access(addr, ID):
    hit = False
    tree = [[addr, ID]]
    victim_counter = phy_assoc
    for i in range(phy_assoc):
        target_set = pick_set(i, addr)
        # compare tags
        if cache_tag[target_set][i] == [addr, ID]:
            hit = True
        else:
            tree.append([target_set, i])
    
    if hit:
        return 1
    else:
        for i in range(1, phy_assoc+1):
            for j in range(phy_assoc):
                if (i-1) != j:
                    target_set = pick_set(j, tree[i][0])
                    if cache_tag[target_set][j][1] == 0:
                        victim_counter = victim_counter + 1
                    tree.append([target_set, j])
    
        print tree
        print victim_counter

        eviction = random.randint(1, victim_counter)
        eviction_index = 0
        for i in range(1, len(tree)):
            if cache_tag[tree[i][0]][tree[i][1]][1] == 0:
                eviction = eviction - 1
            if eviction == 0:
                eviction_index = i 
                break

        print eviction_index
        relocate(tree, eviction_index)
        print_cache()

# attack
init(100)
print_cache()
access(1000, 1)
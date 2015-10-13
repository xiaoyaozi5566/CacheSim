#!/usr/bin/python

import sys
import math
from Crypto.Cipher import AES
from Crypto.Random import random
import numpy as np
import matplotlib.pyplot as plt
import pylab

# Cache parameters
phy_assoc = 4
num_sets = 128
cacheline_size = 64

# calculate tag width, assuming 32-bit address
tag_width = 32 - math.log(cacheline_size, 2) - math.log(num_sets, 2)
tag_range = int(math.pow(2,tag_width) - 1)

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
    for i in range(num_sets):
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
def init():
    # place the victim's cache lines
    victim_counter = phy_assoc*num_sets/2
    tag_range = int(math.pow(2,tag_width) - 1)
    while victim_counter > 0:
        victim_addr = random.randint(0, tag_range)
        victim_way = random.randint(0, phy_assoc-1)
        victim_set = pick_set(victim_way, victim_addr)
        if cache_tag[victim_set][victim_way][0] != -1:
            continue
        else:
            cache_tag[victim_set][victim_way] = [victim_addr, 0]
            victim_counter = victim_counter - 1
    
    # place the victim's cache lines
    attacker_counter = phy_assoc*num_sets/2
    tag_range = int(math.pow(2,tag_width) - 1)
    while attacker_counter > 0:
        attacker_addr = random.randint(0, tag_range)
        attacker_way = random.randint(0, phy_assoc-1)
        attacker_set = pick_set(attacker_way, attacker_addr)
        if cache_tag[attacker_set][attacker_way][0] != -1:
            continue
        else:
            cache_tag[attacker_set][attacker_way] = [attacker_addr, 1]
            attacker_counter = attacker_counter - 1
            
    print "finish initialization"

# relocate for cache eviction
def relocate(tree, index):
    # replacing the first level
    if index <= phy_assoc:
        cache_tag[tree[index][0]][tree[index][1]] = tree[0]
    # replacing the second level
    else:
        L1_index = (index - phy_assoc - 1) / (phy_assoc - 1) + 1
        L2_index = index
        cache_tag[tree[L2_index][0]][tree[L2_index][1]] = cache_tag[tree[L1_index][0]][tree[L1_index][1]]
        cache_tag[tree[L1_index][0]][tree[L1_index][1]] = tree[0]
    
# access a cache line
# False -> miss, True -> hit
def access(addr, ID):
    hit = False
    tree = [[addr, ID]]
    victim_counter = 0
    for i in range(phy_assoc):
        target_set = pick_set(i, addr)
        # compare tags
        if cache_tag[target_set][i] == [addr, ID]:
            hit = True
        else:
            tree.append([target_set, i])
            if cache_tag[target_set][i][1] == ID:
                victim_counter = victim_counter + 1
    
    if hit:
        return True
    else:
        for i in range(1, phy_assoc+1):
            for j in range(phy_assoc):
                if (i-1) != j:
                    target_set = pick_set(j, cache_tag[tree[i][0]][tree[i][1]][0])
                    if cache_tag[target_set][j][1] == ID:
                        victim_counter = victim_counter + 1
                    tree.append([target_set, j])
    
        # print tree
        # print victim_counter
        
        if victim_counter == 0:
            return False

        eviction = random.randint(1, victim_counter)
        eviction_index = 0
        for i in range(1, len(tree)):
            if cache_tag[tree[i][0]][tree[i][1]][1] == ID:
                eviction = eviction - 1
            if eviction == 0:
                eviction_index = i
                break

        # print "eviction_index", eviction_index
        relocate(tree, eviction_index)
        # print_cache()
        return False

# attack
init()
# make a copy of initial cache states
cache_tag_copy = []
for i in range(len(cache_tag)):
    cache_tag_copy.append(cache_tag[i][:])

print_cache()
input_filename = sys.argv[1]
# if insert_flag == 1, insert victim's accesses
insert_flag = int(sys.argv[2])
inputfile = open(input_filename, 'r')
attacker_addr = []
for line in inputfile:
    attacker_addr.append(long(line))
num_rounds = 128

result = []
for i in range(num_rounds):
    each_round = []
    for j in range(len(attacker_addr)):
        hit = access(attacker_addr[j], 1)
        if hit:
            each_round.append(1)
        else:
            each_round.append(0)
    result.append(each_round)
    print "round", i

ratio = len(attacker_addr)*1.0/num_rounds
fig = plt.figure()
ax = fig.add_subplot(111)
ax.set_xlabel("Accesses in one round", fontsize = 20)
ax.set_ylabel("Number of rounds", fontsize = 20)
ax.set_title("Cache misses over time", fontsize = 20)
cax = ax.matshow(result, interpolation='nearest', aspect = ratio)
fig.colorbar(cax)
plt.savefig('hit_miss_'+ str(len(attacker_addr)) + '_' + str(insert_flag) + '_scheme1.pdf', bbox_inches='tight')
plt.close()

cache_tag = []
for i in range(len(cache_tag_copy)):
    cache_tag.append(cache_tag_copy[i][:])
    
print_cache()
result = []
for i in range(num_rounds):
    each_round = []
    for j in range(len(attacker_addr)):
        hit = access(attacker_addr[j], 1)
        if hit:
            each_round.append(1)
        else:
            each_round.append(0)
    result.append(each_round)
    print "round", i
    # insert victim's accesses
    for j in range(len(attacker_addr)*10):
        victim_addr = random.randint(0, tag_range)
        access(victim_addr, 0)

ratio = len(attacker_addr)*1.0/num_rounds
fig = plt.figure()
ax = fig.add_subplot(111)
ax.set_xlabel("Accesses in one round", fontsize = 20)
ax.set_ylabel("Number of rounds", fontsize = 20)
ax.set_title("Cache misses over time", fontsize = 20)
cax = ax.matshow(result, interpolation='nearest', aspect = ratio)
fig.colorbar(cax)
plt.savefig('hit_miss_'+ str(len(attacker_addr)) + '_' + str(insert_flag) + '_scheme2.pdf', bbox_inches='tight')
plt.close()


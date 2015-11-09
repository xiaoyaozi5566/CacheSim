#!/usr/bin/python

from scipy.misc import comb
import sys

def prob(n, m):
    # Total number of combinations
    total_comb = comb(n+m-1, n, exact=True)
    print "total_comb:", total_comb
    num_comb = 0
    for i in range(1, m+1):
        a = comb(m, i, exact=True)
        b = comb(n-i-1, i-1, exact=True)
        num_comb += a*b
    print "num_comb:  ", num_comb
    p = 1.0 - 1.0*num_comb/total_comb
    return p

n = int(sys.argv[1])
m = int(sys.argv[2])
p = prob(n, m)
print "prob:       %.32f" % p
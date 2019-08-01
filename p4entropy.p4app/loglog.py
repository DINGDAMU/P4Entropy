# !/usr/bin/python
# -*- coding:utf-8 -*-
# ###########################
# File Name: loglog.py
# Author: dingdamu
# Mail: dingdamu@gmail.com
# Created Time: 2019-04-23 02:16:20
# ###########################
import math

def trailing_zeroes(num):
    """Counts the number of trailing 0 bits in num."""
    if num == 0:
        return 32  # Assumes 32 bit integer inputs!
    p = 0
    while (num >> p) & 1 == 0:
        p += 1
    return p


def estimate_alpha_m(num_buckets):
    """TODO: Docstring for estimate_alpha_m.

    :arg1: TODO
    :returns: TODO

    """
    alpha = 0.7942 - (2 * (math.pi)**2 + (math.log(2))**2) / (24 * num_buckets)
    return alpha


def estimate_cardinality(max_zeroes, k):
    """Estimates the number of unique elements in the input set values.
    Arguments:
      values: An iterator of hashable elements to estimate the cardinality of.
      k: The number of bits of hash to use as a bucket number;
      there will be 2**k buckets.
    """
    num_buckets = 2 ** k
    alpha_m = estimate_alpha_m(num_buckets)
    return 2 ** (float(sum(max_zeroes)) / num_buckets) * num_buckets * alpha_m

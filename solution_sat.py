#!/usr/bin/env python3
# solution_sat.py
# BIS Project 1 - Unknow cipher
# Michal Ormos (xormos00)
# xormos00@stud.fit.vutbr.cz
# March 2019

from satispy import Variable
from satispy.solver import Minisat
import string

# Constants
# Files
PATH = 'in/'
BISf = 'bis.txt'
BIS_ENCf = 'bis.txt.enc'
GIF_ENCf = 'hint.gif.enc'
SUPER_CIPHER_ENCf = 'super_cipher.py.enc'

N_B = 32
N = 8 * N_B
vs = [Variable("i" + str(i)) for i in range(N)]

solver = Minisat();


def sat_to_number(res, var):
    r = 0
    for i in range(1, N):
        if (res[var[i]]):
            r = r | 1 << (i - 1)
    if (res[var[0]]):
        r = r | 1 << (N - 1)
    return r


def satify_bit(difference, v, v1, v2):
    if not difference:
        return (-v & -v1 & -v2) | (v & (v1 | v2))
    else:
        return (v & -v1 & -v2) | (-v & (v1 | v2))
# def rule(x, y, z):
#     return (x | y | z) & (x | -y | -z) & (-x | y | -z) & (-x | -y | -z)    


def stepReversedSAT(keyMidStream):
    formula = satify_bit(keyMidStream & 1, vs[0], vs[1], vs[2])
    print(formula)
    for i in range(1, N):
        formula = formula & satify_bit((keyMidStream >> i) & 1, vs[i], vs[(i + 1) % N], vs[(i + 2) % N])

    return sat_to_number(solver.solve(formula), vs)

if __name__ == '__main__':
    try:
        PATH = sys.argv[1]
    except:
        pass   

    # read only first 32 bites of files
    bis_txt = open(PATH + BISf, "rb").read(N_B)
    bis_enc = open(PATH + BIS_ENCf, "rb").read(N_B)

    # get 32 bytes keystream as XOR of known plaintex and know cipher text
    keyStream = int.from_bytes(bis_txt, 'little') ^ int.from_bytes(bis_enc, 'little') 
    defaultKeyStream = keyStream;

    for i in range(N // 2):
        keyStream = stepReversedSAT(keyStream)

    # print(keyStream)
    print(keyStream.to_bytes(N_B  , 'little').decode())
    # key = keyStream.to_bytes(N_B, 'little').decode('ascii')
    # print("".join(filter(lambda x: x in string.printable, key)), end='')
#!/usr/bin/env python3
# solution_sat.py
# BIS Project 1 - Unknow cipher
# Michal Ormos (xormos00)
# xormos00@stud.fit.vutbr.cz
# March 2019

from satispy import Variable, Cnf
from satispy.solver import Minisat
import string

# Constants
# Files
PATH = 'in/'
BISf = 'bis.txt'
BIS_ENCf = 'bis.txt.enc'
GIF_ENCf = 'hint.gif.enc'
SUPER_CIPHER_ENCf = 'super_cipher.py.enc'

# Files gathered from manual solution
N_B = 32
N = 8 * N_B

vectorSolution = []
solver = Minisat();

# define bytes by prediate of bool algebra
def satify_bit(difference, v, v1, v2):
    if not difference:
        return (-v & -v1 & -v2) | (v & (v1 | v2))
    else:
        return (v & -v1 & -v2) | (-v & (v1 | v2))

def stepReversedSAT(keyMidStream):
    result = 0

    # create all posibble formulas
    formula = satify_bit(keyMidStream & 1, vectorSolution[0], vectorSolution[1], vectorSolution[2])
    for i in range(1, N):
        formula = formula & satify_bit((keyMidStream >> i) & 1, vectorSolution[i], vectorSolution[(i + 1) % N], vectorSolution[(i + 2) % N])

    # solve individual formulas
    formulaSolved = solver.solve(formula)
    for x in range(1, N):
        if (formulaSolved[vectorSolution[x]]):
            result = result | 1 << (x - 1)
    if (formulaSolved[vectorSolution[0]]):
        result = result | 1 << (N - 1)
    return result

if __name__ == '__main__':
    try:
        PATH = sys.argv[1]
    except:
        pass   

    for i in range(N):
        vectorSolution.append(Variable("i" + str(i)))        

    # read only first 32 bites of files
    bis_txt = open(PATH + BISf, "rb").read(N_B)
    bis_enc = open(PATH + BIS_ENCf, "rb").read(N_B)

    # get 32 bytes keystream as XOR of known plaintex and know cipher text
    keyStream = int.from_bytes(bis_txt, 'little') ^ int.from_bytes(bis_enc, 'little') 
    defaultKeyStream = keyStream;

    for i in range(N // 2):
        keyStream = stepReversedSAT(keyStream)

    print(keyStream.to_bytes(N_B  , 'little').decode())

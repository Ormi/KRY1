#!/usr/bin/env python3
# solution.py
# BIS Project 1 - Unknow cipher
# Michal Ormos (xormos00)
# xormos00@stud.fit.vutbr.cz
# March 2019

import sys

# Constants
# Files
PATH = 'in/'
BISf = 'bis.txt'
BIS_ENCf = 'bis.txt.enc'
GIF_ENCf = 'hint.gif.enc'
SUPER_CIPHER_ENCf = 'super_cipher.py.enc'

################################################################################
# Gathered from decpryphted super_cipher.py.enc

# parser = argparse.ArgumentParser()
# parser.add_argument("key")
# args = parser.parse_args()

# SUB = [0, 1, 1, 0, 0, 1, 0, 1]
SUB = [0, 1, 1, 0, 1, 0, 1, 0]
N_B = 32
N = 8 * N_B

# Next keystream
def step(x):
  x = (x & 1) << N+1 | x << 1 | x >> N-1
  y = 0
  for i in range(N):
    y |= SUB[(x >> i) & 7] << i
  return y

# Keystream init
# keystr = int.from_bytes(args.key.encode(),'little')
# print(keystr)
# for i in range(N//2):
#   keystr = step(keystr)

# Encrypt/decrypt stdin2stdout 
# plaintext = sys.stdin.buffer.read(N_B)
# while plaintext:
#   sys.stdout.buffer.write((
#     int.from_bytes(plaintext,'little') ^ keystr
#   ).to_bytes(N_B,'little'))
#   keystr = step(keystr)
#   plaintext = sys.stdin.buffer.read(N_B)
################################################################################

# Reverse function to function step
# It consist of two parts
# Rotation
#
# Substitution
def stepReversed(keyMidStream):
    # print(SUB)
    # print(keyMidStream)
    SUBcombination = []
    for x in range(len(SUB)):
        # if last bit match to key stream then add to matrix
        if SUB[x] == (keyMidStream & 1): 
            SUBcombination.append(x)
    # print(SUBcombination)            

    # loop each bit of keystream
    for x in range(N):
        tmpSUBcomb = []
        for subTerm in SUBcombination:
            for i in range(len(SUB)):
                # last bit check
                if SUB[i] == (keyMidStream >> x) & 1:
                    # last two bit check
                    if (i & 3) == (subTerm >> x) & 3:
                        subTerm = subTerm | (i << x)
                        # append this combination to others
                        tmpSUBcomb.append(subTerm)
        # set up new combinations for comparision
        SUBcombination = tmpSUBcomb

    # guess last two missing bits
    # if true we have right combination
    # return result to main process and continue
    for x in SUBcombination:
        # TERM
        # first two bits have to match last two
        if (x & 3) == (x >> 256):
            # we have match return it reverse value
            return (x >> 1) & ((1 << N) - 1)

    # otherwise return dead end to main process
    return -1

# decrypt part of super_cipher.py.enc file stored in folder 'in' (this was the first step to crack the cipher)
# after decrypting this file I was able to copy the 'step' function and constants
def xorKnownTexts():
    # get the first part of secret script
    bis_txt = open(PATH + BIS_ENCf, "rb").read()
    bis_enc = open(PATH + BISf, "rb").read()
    script_enc = open(PATH + SUPER_CIPHER_ENCf, "rb").read()

    # get the key stream used to encrypt the message
    key_stream = [a ^ b for (a, b) in zip(bis_txt, bis_enc)]
    # decrypt the script
    decrypted_script = [a ^ b for (a, b) in zip(script_enc, key_stream)]
    # print super_cipher first part
    print(bytes(decrypted_script));

    print("\n")

    # get the second part of secret script
    super_cipher = open(PATH + SUPER_CIPHER_ENCf, "rb").read()
    gif_enc = open(PATH + GIF_ENCf, "rb").read()
    # xor files
    key_stream2 = [a ^ b for (a, b) in zip(super_cipher, gif_enc)]
    # print xor and see result
    print(bytes(key_stream2))

# Project assigment function which with help of keystream brake cipher key
# using all permutations of SUB array
def brakeCipherKey():
    # read only first 32 bites of files
    bis_txt = open(PATH + BISf, "rb").read(N_B)
    bis_enc = open(PATH + BIS_ENCf, "rb").read(N_B)

    # get 32 bytes keystream as XOR of known plaintex and know cipher text
    keyStream = int.from_bytes(bis_txt, 'little') ^ int.from_bytes(bis_enc, 'little') 
    defaultKeyStream = keyStream;

    keyStream = defaultKeyStream

    # loop as many times as was in original cipher scrit
    for z in range(N//2):
        # if reverse steo function returns -1 it means DEAD END
        # go to next SUB combination
        if(keyStream == -1):
            break            
        keyStream = stepReversed(keyStream)

    # if reverse step function returns -1 start again with next iteration
    if(keyStream == -1):
        pass        
    # otherwise try to decode it to ascii
    # if it will crash bytes are wrond, continue to next iteration
    try:
        print(keyStream.to_bytes(N_B  , 'little').decode())
    except:
        pass
    # otherwise we have key!
    else:
        exit(0)

if __name__ == '__main__':
    try:
        PATH = sys.argv[1]
    except:
        pass    
    brakeCipherKey()
    # xorKnownTexts();   
import random, sys, os, rabinMiller, cryptomath

def generateKey(keySize):
    p = rabinMiller.generateLargePrime(keySize)
    while True:
        q = rabinMiller.generateLargePrime(keySize)
        if p == q:
            continue
        break
    n = p * q

    while True:
        # Keep trying random numbers for e until one is valid.
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if cryptomath.gcd(e, (p - 1) * (q - 1)) == 1:
            break

    d = cryptomath.findModInverse(e, (p - 1) * (q - 1))

    publicKey = (n, e)
    privateKey = (n, d)

    return (publicKey, privateKey)

# def makeKeyFiles(keySize):
#     publicKey, privateKey = generateKey(keySize)
#
#     # fo = open('Public Key.txt', 'w')
#     # fo.write('%s,%s,%s' % (keySize, publicKey[0], publicKey[1]))
#     with open('Public Key.txt','w') as f:
#         f.write('%s,%s,%s' % (keySize, publicKey[0], publicKey[1]))
#
#     with open('Private Key.txt','w') as f:
#         f.write('%s,%s,%s' % (keySize, privateKey[0], privateKey[1]))
#
#     f.close()




    # ff = open('Private Key.txt', 'w')
    # ff.write('%s,%s,%s' % (keySize, privateKey[0], privateKey[1]))




import aespassword_generator as aesgen

import getHash
#message = '|*cndz9</gTlKiwYesshigh'
#
def check_keylen(path):
    with open(path,'r') as f:
        data = (f.read()).split(',')
        keylen = data[0]
        return keylen

def random_padd_gen(msg,keylen):

    if len(msg) == 16:
        if keylen == '1024':
            rpadd = aesgen.pass_gen(45)
        elif keylen == '2048':
            rpadd = aesgen.pass_gen(173)
        elif keylen == '4096':
            rpadd = aesgen.pass_gen(429)
        else:
            msg.showerror('Invalid format','Your input is invalid format')
    elif len(msg) == 24:
        if keylen == '1024':
            rpadd = aesgen.pass_gen(37)
        elif keylen == '2048':
            rpadd = aesgen.pass_gen(165)
        elif keylen == '4096':
            rpadd = aesgen.pass_gen(421)
        else:
            msg.showerror('Invalid format','Your input is invalid format')
    elif len(msg) == 32:
        if keylen == '1024':
            rpadd = aesgen.pass_gen(29)
        elif keylen == '2048':
            rpadd = aesgen.pass_gen(157)
        elif keylen == '4096':
            rpadd = aesgen.pass_gen(413)
        else:
            msg.showerror('Invalid format','Your input is invalid format')

    return rpadd

def pkcs(path,message,hashpath):
    keylen = check_keylen(path)
    rpadd = random_padd_gen(message,keylen)
    hashval = getHash.gethash(hashpath)
    eb = '02'+rpadd+'0'+message+hashval
    return eb

def extract_key(padmsg):
        keystr = padmsg[:-64]
        key = ''
        for char in reversed(keystr):

            if char == '0':
                break
            else:
                key = key + char
                #print(key)
        key = key[::-1]
        return key

def extract_hash(padmsg):
    hashstr = padmsg[-64:]
    return hashstr



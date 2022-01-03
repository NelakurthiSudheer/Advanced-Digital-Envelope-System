import os
#import time

#import aes128 as aes
global iv

def xor(temp,vec):
    for i in range(16):
        temp[i] = temp[i]^vec[i]
    return temp

def make_iv():

    symbols = 'B8s&,#6KH,Dx+"&U'

    IV = [ord(symbol) for symbol in symbols]
    return IV

def encrypt(in_path,aeskey,mode):
    #input_path = os.path.abspath(in_path)
    if len(aeskey) == 16:
        import aes128 as aes

    elif len(aeskey) == 24:
        import aes192 as aes

    elif len(aeskey) == 32:
        import aes256 as aes

    iv = make_iv()

    for symbol in aeskey:
        if ord(symbol) > 0xff:
            print('That key won\'t work. Try another using only latin alphabet and numbers')
            continue
    aeskey = aes.key_expansion(aeskey)

    with open(in_path, 'rb') as f:
        data = f.read()

    crypted_data = []
    temp = []

    for byte in data:
        temp.append(byte)
        if len(temp) == 16:
            # print(temp)
            if mode == 'cbc':
                temp = xor(temp, iv)
                # print(temp)
                crypted_part = aes.encrypt(temp, aeskey)
                iv = list(crypted_part)
                crypted_data.extend(crypted_part)
                del temp[:]
            else:
                crypted_part = aes.encrypt(temp, aeskey)
                crypted_data.extend(crypted_part)
                del temp[:]

    else:
        # padding v1
        # crypted_data.extend(temp)

        # padding v2
        if 0 < len(temp) < 16:
            # print('here')
            if mode == 'cbc':
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces):
                    temp.append(0)
                if mode == 'cbc':
                    temp = xor(temp, iv)
                crypted_part = aes.encrypt(temp, aeskey)
                if mode == 'cbc':
                    iv = list(crypted_part)
                crypted_data.extend(crypted_part)
            else:
                empty_spaces = 16 - len(temp)
                for i in range(empty_spaces):
                    temp.append(0)
                crypted_part = aes.encrypt(temp, aeskey)
                crypted_data.extend(crypted_part)

    return crypted_data

def decrypt(in_path,aeskey,mode):
    if len(aeskey) == 16:
        import aes128 as aes
    elif len(aeskey) == 24:
        import aes192 as aes
    elif len(aeskey) == 32:
        import aes256 as aes

    iv = make_iv()
    aeskey = aes.key_expansion(aeskey)
    input_path = os.path.abspath(in_path)


    with open(input_path, 'rb') as f:
        data = f.read()

    decrypted_data = []
    temp = []
    for byte in data:
        temp.append(byte)
        #iv2.append(byte)
        if len(temp) == 16:
            # print(iv)
            # print(temp)
            if mode == 'cbc':
                decrypted_part = aes.decrypt(temp, aeskey)
                decrypted_part = xor(decrypted_part, iv)
                iv = list(temp)
                decrypted_data.extend(decrypted_part)
                del temp[:]
            else:
                decrypted_part = aes.decrypt(temp, aeskey)
                decrypted_data.extend(decrypted_part)
                del temp[:]


    return decrypted_data




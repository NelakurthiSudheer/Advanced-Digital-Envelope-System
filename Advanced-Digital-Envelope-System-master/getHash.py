import hashlib
import binascii
import textwrap
def gethash(path):
    with open(path,'rb') as f:
        data = f.read()

    digest = hashlib.sha256(data).hexdigest()
    return digest



# print(len(gethash('E:\Key File\data.txt')))
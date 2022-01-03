import string
import random


def pass_gen(keysize):
    ran_password = ''
    word_list = tuple(string.digits[1:] + string.punctuation + string.ascii_letters)
    for i in range(keysize):
        ran_num = random.randrange(0,93)
        ran_password = ran_password + word_list[ran_num]
    return ran_password

pass_gen(32)



import random
import numpy as np
import hashlib
import pickle
from hatt.chiper import *

aes = None

def read_init_crp(rand_puf):
    return rand_puf.randint(0, 65535)

def get_puf(rand_puf):
    return rand_puf.randint(0, 65535)

def get_pid(id_a, r_i, n_id):
    global aes
    aes = AESCipher(str(r_i))
    return hashlib.md5( (str(id_a) + str(r_i) + str(n_id)).encode('utf-8') ).hexdigest()

def get_m1(n_id, pid, s_b, s_w, n_1, r_i):
    enc_data = [ aes.encrypt(s_b) , aes.encrypt(s_w), aes.encrypt(n_1)]
    
    m1 = {'n_id' : n_id, 'pid' : pid, 'enc_data' : enc_data}

    return m1

def get_m_2(id_a, n1, n2, r):
    id_enc = ""
    for i in range(len(id_a)):
        id_enc += str( aes.encrypt(ord(id_a[i])))

    m2 = {'id_a' : id_enc, 'n1' : aes.encrypt(n1), 'n2' : aes.encrypt(n2)}

    return m2

def get_m_s(sigma, n1, n2, r):
    sigma_enc = []
    for i in sigma:
        sigma_enc.append( aes.encrypt(i) )

    m_s = {'sigma_enc' : sigma_enc, 'n1' : aes.encrypt(n1), 'n2' : aes.encrypt(n2)}

    return m_s


def get_i_1(id_a, id_s, m_1, n_1, r_i):
    return hashlib.md5( (str(id_a) + str(id_s) + str(m_1) + str(n_1) + str(r_i)).encode('utf-8') ).hexdigest()

def get_i_2(id_a, id_s, m2, n1, n2, r):
    return hashlib.md5( (str(id_a) + str(id_s) + str(m2) + str(n1) + str(n2) + str(r)).encode('utf-8') ).hexdigest()

def get_i_3(n1, n2, r):
    return hashlib.md5( (str(n1) + str(n2) + str(r) ).encode('utf-8') ).hexdigest()

def get_i_4(id_a, id_s, m_s, r):
    return hashlib.md5( (str(id_a) + str(id_s) + str(m_s) + str(r)).encode('utf-8')).hexdigest()

def verify_pid(id_a, m1, r):
    n_id = m1['n_id']
    pid = get_pid(id_a, r, n_id)

    if pid != m1['pid']:
        print("ERROR: PID NOT SAME IN STAGE2")
        exit()

def verify_i1(old_i1, id_a, id_s, m1, r, n_1):
    i1 = get_i_1(id_a, id_s, m1, n_1, r)

    if old_i1 != i1:
        print("ERROR: I1 NOT SAME IN STAGE2")
        exit()

def verify_i2(old_i2, id_a, id_s, m2, n1, n2, r):
    i2 = get_i_2(id_a, id_s, m2, n1, n2, r)

    if old_i2 != i2:
        print('ERROR: I2 is NOT SAME IN STAGE3')
        exit()

def verify_i3(old_i3, n1, n2, r):
    i3 = get_i_3(n1, n2, r)

    if old_i3 != i3:
        print("ERROR: I3 NOT SAME IN STAGE4")
        exit()

def verify_i4(old_i4, id_a, id_s, ms, r):
    i4 = get_i_4(id_a, id_s, ms, r)

    if old_i4 != i4:
        print("ERROR: I$ NOT SAME IN STAGE5")
        exit()
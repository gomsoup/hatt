import socket
import random
from hatt.common import *
from hatt.sock import *
from hatt.memBlock import *
from hatt.chiper import *
from _thread import *

init_c = ord('C')

rand_s_b = random.Random()
rand_s_w = random.Random()
rand_n_1 = random.Random()
rand_n_id = random.Random()
rand_r_i = random.Random()
rand_puf = random.Random()

rand_s_b.seed(ord('b'))
rand_s_w.seed(ord('w'))
rand_n_1.seed(ord('n'))
rand_n_id.seed(ord('A'))
rand_puf.seed(init_c)

id_a = 'IDA'
id_s = 'IDS'

s_b, s_w = 0, 0
r = 0 
is_init = True

def decrypt_n1_n2(enc_data, r):
    global aes
    aes = AESCipher(str(r))

    n1 = aes.decrypt(enc_data['n1'])
    n2 = aes.decrypt(enc_data['n2'])
    
    return n1, n2

def decrypt_ms(ms, r):
    n1 = aes.decrypt(ms['n1'])
    n2 = aes.decrypt(ms['n2'])

    sigma = []
    for i in ms['sigma_enc']:
        sigma.append(aes.decrypt(i))

    return sigma, n1, n2

def verify_sigma(sigma, prover_sigma):
    for i in range(len(sigma)):
        if( str(sigma[i]) != str(prover_sigma[i]) ):
            print("ERROR: SIGMA NOT SAME!!!!")
            exit()

def stage_1():
    global s_b, s_w, r

    #stage 1
    r = read_init_crp(rand_puf)
    n1, n_id = rand_n_1.randint(0, 65535), rand_n_id.randint(0, 65535)

    pid = get_pid(id_a, r, n_id)
    s_b, s_w = rand_s_b.randint(0, 65535), rand_s_w.randint(0, 65535)
    
    m1 = get_m1(n_id, pid, s_b, s_w, n1, r)
    i1 = get_i_1(id_a, id_s, m1, n1, r)

    return m1, i1

def stage_3(m2, i2):
    n1, n2 = decrypt_n1_n2(m2, r)
    
    print('Verifying I2..')
    verify_i2(i2, id_a, id_s, m2, n1, n2, r)

    i3 = get_i_3(n1, n2, r)

    return i3

def stage_5(ms, i4):
    prover_sigma, n1, n2 = decrypt_ms(ms, r)

    print('Verifying I4..')
    verify_i4(i4, id_a, id_s, ms, r)
    
    stream = open('C:\\Users\\overflow\\Desktop\\a', 'rb')
    sigma = attBlock(stream, s_b, s_w, r)
    stream.close()
    print('Verifying Sigma...')
    verify_sigma(sigma, prover_sigma)

def solver(cs):
    m1, i1 = stage_1()
    print('s_b: ' + str(s_b) + ' s_w: ' + str(s_w) + ' r: ' + str(r))
    send_to_target(cs, m1)
    send_to_target(cs, i1)

    m2 = recv_from_target(cs)
    i2 = recv_from_target(cs)    
    i3 = stage_3(m2, i2)

    send_to_target(cs, i3)

    ms = recv_from_target(cs)
    i4 = recv_from_target(cs)
    
    stage_5(ms, i4)

    cs.close()

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 9949))
    print("Socket opened..")
    s.listen()

    while True:
        cs, caddr = s.accept()
        print("Accepted connection req from " + str(caddr))
        start_new_thread(solver, (cs,))
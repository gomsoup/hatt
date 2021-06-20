import socket
import random
from hatt.sock import *
from hatt.common import *
from hatt.memBlock import *
from _thread import *
import time

id_a = 'IDA'
id_s = 'IDS'

init_c = ord('C')

rand_n_2 = random.Random()
rand_puf = random.Random()

rand_puf.seed(init_c)
rand_n_2.seed('N2')

r = 0
s_b, s_w =0, 0
is_init = False

def decrypt_m1_enc_data(enc_data, r):
    s_b = enc_data[0] ^ r
    s_w = enc_data[1] ^ r
    n_1 = enc_data[2] ^ r

    return s_b, s_w, n_1

def stage_2(m1, i1):
    global r, s_b, s_w
    r = get_puf(rand_puf)

    print('Verifying PID..')
    verify_pid(id_a, m1, r)

    print('Verirying I1..')
    s_b, s_w, n1 = decrypt_m1_enc_data(m1['enc_data'], r)
    verify_i1(i1, id_a, id_s, m1, r, n1)

    n2 = rand_n_2.randint(0, 65535)
    m2 = get_m_2(id_a, n1, n2, r)
    i2 = get_i_2(id_a, id_s, m2, n1, n2, r)

    return n1, n2, m2, i2

def stage_4(n1, n2, i3):
    print('Verifying I3..')
    verify_i3(i3, n1, n2, r)

    stream = open('./b', 'rb')
    sigma = attBlock(stream, s_b, s_w, r)
    stream.close()
    m_s = get_m_s(sigma, n1, n2, r)
    i4 = get_i_4(id_a, id_s, m_s, r)

    return m_s, i4

def solver(s):
    print('Connected.')
    m1 = recv_from_target(s)
    i1 = recv_from_target(s)

    n1, n2, m2, i2 = stage_2(m1, i1)
    print('s_b: ' + str(s_b) + ' s_w: ' + str(s_w) + ' r: ' + str(r))
    send_to_target(s, m2)
    send_to_target(s, i2)
    
    i3 = recv_from_target(s)
    m_s, i4 = stage_4(n1, n2, i3)

    send_to_target(s, m_s)
    send_to_target(s, i4)



if __name__ == '__main__':
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Trying to connect verifier..')
        s.connect(('127.0.0.1', 9949))
        start_new_thread(solver, (s,))
        time.sleep(5)
        


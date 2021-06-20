import pickle
import socket

def send_to_target(cs, obj):
    obj = pickle.dumps(obj)

    size = len(obj)
    cs.send((size).to_bytes(4, 'little'))
    ack = cs.recv(4)

    if ack != b'RECV':
        print("Error: send obj size to prover. ACK is not vaild!!")
        exit()
    
    cs.send(obj)
    ack = cs.recv(4)
    if ack != b'RECV':
        print("Error: send obj to prover. ACK is not vaild!!")
        exit()

def recv_from_target(s):
    size = s.recv(4)
    s.send(b'RECV')

    size = int.from_bytes(size, 'little')
    obj = s.recv(size)
    s.send(b'RECV')

    obj = pickle.loads(obj)
    
    return obj
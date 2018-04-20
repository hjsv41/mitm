import socket as sk

HOST = 'localhost'
PORT = 2156
BUFSIZ = 1024
ADDR = (HOST, PORT)

csock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
csock.connect(ADDR)
while 1:
    data = raw_input('... ')
    csock.send(data)
    data = csock.recv(1024)
    if not data:
        break
    print data

csock.close()

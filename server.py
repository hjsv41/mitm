import socket as sk
HOST = 'localhost'
PORT = 2156
BUFSIZ = 1024
ADDR = (HOST, PORT)
ssock = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
ssock.bind(ADDR)
ssock.listen(2)

while 1:
    print "no conn"
    csock, addr = ssock.accept()
    print "connected from ", addr

    while 1:
        data = csock.recv(BUFSIZ)
        if not data:
            break
        csock.send("echoed "  data)

    csock.close()
ssock.close()

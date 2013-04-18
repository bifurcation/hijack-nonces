#!/usr/bin/env python

import socket
from time import sleep
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto import Random

### RSA public key
RSA_n = long("c63fb46c1fe2e7f916fd5071c482363677b37d02b2e657c24daee468b14d8e2620d2935223a5b074a6fee2b63962b476fda3098ed0f83839c9866fa58e19fac99943e9aebcd76920b0d439ca02135523922943d63f39be87a03d2a91b8bf91506faf0cb6f597a59fe90e3b7e2100fc170c7ec43750d3e20f7b46b2a6c46d826cb0c2ed634bfc39130a056e7f12993123f5ca8e0cdf1d2d1d8371b9791978f19ec43f1272bef1f2ea88857a350c6bd16d46bbd7dddcbd8fb73c11af73ead8831b48f256325825de9b3364c719333d9a10ba23225de3da9805f8baded55a6e1acd0be284f191b5425dba8df02e286512af76bbf521f47d51019a104f2659903cf3", 16);
RSA_e = long("10001", 16);
PSS = PKCS1_PSS.new(RSA.construct((RSA_n, RSA_e)))

### UDP parameters
HOST = "localhost"
PORT = 9999
SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

i = 1
while True:
    n = Random.get_random_bytes(32)
    SOCK.sendto(n, (HOST,PORT))
    print "probe ({0}) to {1}:{2} | sent {3} | ".format(i, HOST, PORT, n.encode("hex")),
    sig = SOCK.recv(4096)
    if PSS.verify(SHA256.new(n), sig):
        print "VALID"
    else:
        print "INVALID"
    i += 1
    sleep(1)





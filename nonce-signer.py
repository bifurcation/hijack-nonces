#!/usr/bin/env python

import SocketServer 
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto import Random

### RSA key pair
# To generate:
# >>> from Crypto.PublicKey import RSA
# >>> key = RSA.generate(2048)
# >>> hex(key.n)
# >>> hex(key.e)
# >>> hex(key.d)
RSA_n = long("c63fb46c1fe2e7f916fd5071c482363677b37d02b2e657c24daee468b14d8e2620d2935223a5b074a6fee2b63962b476fda3098ed0f83839c9866fa58e19fac99943e9aebcd76920b0d439ca02135523922943d63f39be87a03d2a91b8bf91506faf0cb6f597a59fe90e3b7e2100fc170c7ec43750d3e20f7b46b2a6c46d826cb0c2ed634bfc39130a056e7f12993123f5ca8e0cdf1d2d1d8371b9791978f19ec43f1272bef1f2ea88857a350c6bd16d46bbd7dddcbd8fb73c11af73ead8831b48f256325825de9b3364c719333d9a10ba23225de3da9805f8baded55a6e1acd0be284f191b5425dba8df02e286512af76bbf521f47d51019a104f2659903cf3", 16);
RSA_e = long("10001", 16);
RSA_d = long("1af56ec3855285d9099748e92f9fc55f82c795a8584b9a8381acd6c2a5d9b60ad94bc95cd21c25f2b702d231957c26ae47af740d47bd7967e24fb5befda3eac69f60ecd62637e4c3dd47fed3c994776f6ee0cda8c4d045688c11c5482ba7614b5ee49f06023facf621eb1d8bf950f8f6e96c13a2b20b1e229cd0f05a5d3bc7106366817a0a73198ff3907e356c02a1eaeb592681301413bda843cbdadcd1a06155aa3effcaf7c9094485021a7677dfdfedd233a806d5292f2aad836d1d621856ca1cefae336cff494bc420366998b8fceea30d7b0fc6ff8e4e35ddb348b6734940c938ade3c1ce5db76fae128b6dadb3c24427798641ac773187d7a0f82c9e01", 16);
PSS = PKCS1_PSS.new(RSA.construct((RSA_n, RSA_e, RSA_d)))

class NonceSigningHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        signature = PSS.sign(SHA256.new(data))        
        socket.sendto(signature, self.client_address)

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999
    server = SocketServer.UDPServer((HOST, PORT), NonceSigningHandler)
    server.serve_forever()

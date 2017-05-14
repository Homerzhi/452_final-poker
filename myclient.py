import socket

from Crypto.PublicKey import RSA
from Crypto import Random

from Crypto.Cipher import ARC4

#Generate private and public keys
key=Random.new().read
pr=RSA.generate(1024,key)
pb=pr.publickey()

    
host='127.0.0.1'
port=5000

s=socket.socket()
s.connect((host,port))   #connect takes a turple of a host address and port.


message=pb.exportKey()
s.send('client_key='+message+'\n')
print 'client sent public key'

data=s.recv(1024)
data=data.replace("public_key=",'')
data=data.replace('\r\n','')
spb=RSA.importKey(data)
print 'client received server public key'

sessionkey=s.recv(1024)
sessionkey=eval(sessionkey)
sessionkey=pr.decrypt(sessionkey)
print "client received sessionkey:",sessionkey

message='-ready to receive numbers-'
while message!='q':

    sk= ARC4.new(sessionkey)
    m=sk.encrypt(message)

    s.send(m)
    print "encrypted message:",m
    print "plain text sent:",message
    
    recvdata=s.recv(1024)
    
    sk=ARC4.new(sessionkey)
    recvdata=sk.decrypt(recvdata)
              
    recvdata=map(int, recvdata.split())
    data=max(recvdata)
    print "recieved from ", s.getsockname(), " :"+str(recvdata)
    message=raw_input("Press Enter to continoue->")
    message=str(data)
    
s.close()


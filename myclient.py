import socket

from Crypto.PublicKey import RSA
from Crypto import Random

from Crypto.Cipher import ARC4
from random import randint
#Generate private and public keys
key=Random.new().read
pr=RSA.generate(1024,key)
pb=pr.publickey()

    
host='127.0.0.1'
port=5000

s=socket.socket()
s.connect((host,port))   #connect takes a turple of a host address and port.


cl_publickey=pb.exportKey()
s.send('client_key='+cl_publickey+'\n')
print 'client sent public key'

data=s.recv(1024)
data=data.replace("public_key=",'')
data=data.replace('\r\n','')
spb=RSA.importKey(data)
print 'client received server public key'

DHkey=s.recv(1024)
DHkey=eval(DHkey)
DHkey=pr.decrypt(DHkey)
aqy=map(int, DHkey.split())
x=randint(3,aqy[1])
y=aqy[0]**x%aqy[1]            #public key, need to send 

#session_key=(server_public_key)**(own_private_key)%q
sessionkey=str(aqy[2]**x%aqy[1])
print "client received a,q,y:",aqy, " and compute session key:",sessionkey

DH_public_key=str(y)
DH_public_key=str(spb.encrypt(DH_public_key,32))
s.send(DH_public_key)

message='ready to receive'
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
    if recvdata:
        data=max(recvdata)
        print "recieved from ", s.getsockname(), " :"+str(recvdata)
    else:
        data=0
        print 'recieved nothing'
    message=raw_input("Press Enter to continoue->")
    message=str(data)
    
s.close()


import socket
import select
import sys
import Queue
from random import randint
import signal

from Crypto.PublicKey import RSA
from Crypto import Random

from Crypto.Cipher import ARC4

#Generate private and public keys
key=Random.new().read
pr=RSA.generate(1024,key)
pb=pr.publickey()

        
#def main():
clients={}
clientnames=[]
clientsessionkey={}
clientPublicKey={}
host='127.0.0.1'
port=5000

#create a tcp socket
server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#set up a non blocking socket
server.setblocking(0)

#bind
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host,port))   #bind takes a turple of a host address and port.

#listen for incoming connections by given number
server.listen(2)
# Trap keyboard interrupts



inputs=[server]
outputs=[]
message_queues={}

def sighandler(signum, frame):
    # Close the server
    print 'Shutting down server...'
    # Close existing client sockets
    if outputs:
        for o in outputs:
            o.close()
    server.close()
    
signal.signal(signal.SIGINT, sighandler)


#receive and send
while inputs:
    #get all of the sockets in reading list.
    reading, writing, exceptional = select.select(inputs, outputs, inputs)
    
    #handle inputs
    for s in reading:
        if s==server:
            #waiting for connection, accept
            connection,addr=s.accept()      #accepts a connection when found, returns new socket
            print 'connection from:', connection.getpeername()[1] #str(addr)
            clients[connection.getpeername()[1]]=[]   
            clientnames.append(connection.getpeername()[1])
            
            connection.send('public_key='+pb.exportKey()+'\n')
            data=connection.recv(1024)
            data=data.replace("client_key=",'')
            data=data.replace('\r\n','')
            clientPublicKey[connection.getpeername()] =data
            
            #todo try to send session key
            sessionkey=str(randint(10000,155555))    #here can use random, but keep difficult we use 1234
            clientsessionkey[connection.getpeername()]=sessionkey
            client_publickey=RSA.importKey(clientPublicKey[connection.getpeername()])
            sessionkey=str(client_publickey.encrypt(sessionkey,32))
            connection.send(sessionkey)
            
            
            connection.setblocking(0)
            inputs.append(connection)
            message_queues[connection]=Queue.Queue()
        else:#established connection with a client that has sent data.
            #print s.getpeername()  
            data=s.recv(1024)
            
            if data:                   
                message_queues[s].put(data)
                #print '01 received: ', data, ' from ', s.getpeername()
                #add output channel for response.
                if s not in outputs:
                    outputs.append(s)
            else:
                s.close()
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
    for s in writing:
        try:
            recv_msg=message_queues[s].get_nowait()

            sk=clientsessionkey[s.getpeername()]
            clientSK=ARC4.new(sk)
            recv_msg=clientSK.encrypt(data)
            
            
            if recv_msg.isdigit():
                clients[s.getpeername()[1]].append(int(recv_msg))

            print  s.getpeername()[1], ' received: ', recv_msg
            print  s.getpeername()[1], ' numbers chosen:', clients[s.getpeername()[1]]
                
            if clientnames:
                if (len(clientnames))==2:
                    if len(clients[clientnames[0]])==3 and len(clients[clientnames[1]])==3:
                        max1=max( map(int, clients[clientnames[0]]))
                        max2=max( map(int, clients[clientnames[1]]))
                        if max1 > max2:
                            print clientnames[0], ' win'
                        elif max1==max2:
                            print clientnames[0], ' and ', clientnames[1], ' are even'
                        else:
                            print clientnames[1], ' win'
                            
                        break

            
        except Queue.Empty:
            #no message waiting.
            outputs.remove(s)
        else:
            #todo: need to check if sent three numbers, then stop sending
            #generate 3 numbers between 1 to 15
            next_msg=str(randint(1,15))+" "+str(randint(1,15))+" "+str(randint(1,15))
            print 'sending ', next_msg, ' to ', s.getpeername()

            sk=clientsessionkey[s.getpeername()]
            clientSK=ARC4.new(sk)
            next_msg=clientSK.encrypt(next_msg)

            
            s.send(next_msg)
    for s in exceptional: 
        print 'handling exceptional condition for ', s.getpeername()
        s.close()
        inputs.remove(s)
        outputs.remove(s)
        del message_queues[s]
            
            
            
c.close()


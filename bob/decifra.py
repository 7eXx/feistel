#!/usr/bin/env python3
import socket
import hashlib
import os

# costanti di connessione
my_ip = "192.168.0.110"
my_port = 65432
key_c = 3
file_dest = "ricevuto.jpg"

ENCRYPTED = "encrypted_rcv"

def get_ext(path):
    l = path.split('.')
    return '.'+l[-1]

def get_md5(path):
    md5 = hashlib.md5()
    tot_size = os.stat(path).st_size
    tot_read = 0
    with open(path,'rb') as f:
        while tot_read < tot_size:
            data = f.read(1024)
            md5.update(data)
            tot_read += len(data)
    return md5.hexdigest()

def function(block,key):
    nk = 3*key**4
    bk = bin(nk)[2:]
    bk = bk[-32:] #32 bit meno significativi
    bk = bk.zfill(32)
    new_key = bytes()
    new_block = bytes()
    #generiamo tutti i byte dalla stringa binaria
    while bk:
        value = bk[:8]
        new_key += bytes([int(value,2)])
        bk = bk[8:]
    #xor byte a byte
    for i in range(4):
        new_block += bytes([block[i]^new_key[i]])
    return new_block

def unfeistel(block,keys):
    l = block[:4]
    r = block[4:]
    
    for key in reversed(keys):
        new_r = l
        f_l = function(l,key)
        #xor byte a byte
        new_l = bytes()
        for i in range(4):
            new_l += bytes([r[i]^f_l[i]])
        l,r = new_l,new_r
    
    new_block = l + r
    return new_block
    

def feistel_blocks(path,keys,padding):
    size = os.stat(path).st_size
    bytes_read = 0
    last_value = 0
    with open(path,'rb') as f, open(file_dest,'wb') as g:
        while bytes_read < size:
            old = f.read(8)
            new = unfeistel(old,keys)
            if bytes_read == size-8:
                new = new[:8-padding]
            bytes_read += len(old) #len(old) perché l'ultimo new potrebbe avere padding
            g.write(new)
########### stampa elaborazione avanzamento
            value = int(bytes_read/size*100)
            if (value!=last_value):
                print(value,'%    ',bytes_read,'/',size,'con chiave',keys[0])
                last_value = value

def generate_keys(original):
    keys = []
    keys.append(original)
    
    bitkey = bin(original)[2:].zfill(32)
    
    bitkey2 = bitkey[8:]+bitkey[:8]
    keys.append(int(bitkey2,2))
    
    bitkey3 = bitkey2[8:]+bitkey2[:8]
    keys.append(int(bitkey3,2))
    
    bitkey4 = bitkey3[8:]+bitkey3[:8]
    keys.append(int(bitkey4,2))
    
    return keys

def feistel_decrypter(path,passkey,padding):
    keys = generate_keys(passkey)
    feistel_blocks(path,keys,padding)

if __name__ == '__main__':
    
    #ricevo l'MD5 originale, i byte di padding e il file cifrato
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((my_ip,my_port))
    s.listen(1)
    bytes_read = 0

    print ("in attesa della connessione....")
    clientsocket, address = s.accept()

    with open(ENCRYPTED+get_ext(file_dest),'wb') as f:

        data = clientsocket.recv(32)
        md5_old = data.decode()
        print('arrivato MD5')
        data = clientsocket.recv(1)
        padding = int(data.decode())
        print('arrivato padding')
        data = clientsocket.recv(20)
        size = int(data.decode())
        print('size:',size)
        while bytes_read < size:
            data = clientsocket.recv(1024)
            f.write(data)
            bytes_read += len(data)
            #print(data)

    s.close()
    
    print('- Dati Ricevuti -')
    feistel_decrypter(ENCRYPTED+get_ext(file_dest),key_c,padding)
    
    #verifica decifratura (confronto md5)
    md5_new = get_md5(file_dest)
    if md5_new == md5_old:
        print('- Decifratura Riuscita -')
    else:
        print('- Decifratura Fallita -')
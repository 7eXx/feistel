#!/usr/bin/env python3
import argparse
import socket
import hashlib
import os

# costanti di connessione e chiavi
ip_dest = "192.168.0.115"
ip_cracker = "192.168.0.111"
port_dest = 65432
key_c = 3
path_file = "file_originale.jpg"

ENCRYPTED = "encrypted"

#classe per la cifrazione del file immagine 
#(utilizza key e immagine.tiff)
# funzione = 3*key^4 e tronca i bit più significativi
# byte-padding con valore dei bit aggiunti
def encrypter(path,passkey):
    keys = generate_keys(passkey)
    feistel_blocks(path,keys)

def get_ext(path):
    l = path.split('.')
    return '.' + l[-1]


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
    bk = bin(nk)[2:] #32 bit meno significativi
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

def feistel(block,keys):
    l = block[:4]
    r = block[4:]
    
    for key in keys:
        new_l = r
        f_r = function(r,key)
        #xor byte a byte
        new_r = bytes()
        for i in range(4):
            new_r += bytes([ l[i]^f_r[i] ])
        l,r = new_l,new_r
    
    new_block = l + r
    return new_block

def feistel_blocks(path,keys):
    size = os.stat(path).st_size
    bytes_read = 0
    work = 0
    path1 = 'encrypted'+get_ext(path_file)
    value = 0
    last_value = 0

    with open(path,'rb') as f, open(path1,'wb') as g:
        while bytes_read <= size:
            old = f.read(8)
            if len(old)<8: 
                global padding#dichiaro che la variabile è globale
                padding = 8-len(old)
                old += bytes(8-len(old)) 
            new = feistel(old, keys)
            g.write(new)
            bytes_read += len(new)
########### stampa elaborazione avanzamento
            value = int(bytes_read/size*100)
            if (value!=last_value):
                print(value,'%    ',bytes_read,'/',size)
                last_value = value ###
    print('------ Encryption completed! ------')
    print('original file dimension:  ',size,'bytes')
    size1 = os.stat(path1).st_size
    print('encrypted file dimension: ',size1,'bytes')
    padding = size1 - size
    print('       necessary padding: ',padding,'bytes')

def generate_keys(original):
    keys = []
    keys.append(original)   #ex orig= 3 -> 11
    
    bitkey = bin(original)[2:].zfill(32) # 00000000000000000000000000000011
    
    bitkey2 = bitkey[8:]+bitkey[:8]     #00000000000000000000001100000000
    keys.append(int(bitkey2,2))         # converte da binario a base 10 -> 768
    
    bitkey3 = bitkey2[8:]+bitkey2[:8]   #00000000000000110000000000000000
    keys.append(int(bitkey3,2))         # converte da binario a base 10 -> 196608
    
    bitkey4 = bitkey3[8:]+bitkey3[:8]   #00000011000000000000000000000000
    keys.append(int(bitkey4,2))         # converte da binario a base 10 -> ‭50331648‬
    
    return keys

#salvo argomenti 
if __name__ == '__main__':

    #apro e leggo il file immagine, quindi ne calcolo l'md5 
    # hashlib.md5(open('immagine.tiff').read()).hexdigest()
    md5 = hashlib.md5()

    md5_orig = get_md5(path_file)

    #cripto il file originale
    encrypter(path_file, key_c)

    #dimensone file e padding
    orig_size = os.stat(path_file).st_size
    enc_size = os.stat(ENCRYPTED + get_ext(path_file)).st_size
    pad = enc_size - orig_size

    #apro la socket per la trasmissione al destinatario
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_dest, port_dest))
    except Exception as e:
        print('errore connessione al destinatario')

    else:

        #invio md5 e file criptato

        s.sendall(md5_orig.zfill(32).encode())
        s.sendall(str(pad).encode())
        s.sendall(str(enc_size).zfill(20).encode())


        tot_dim = os.stat(ENCRYPTED+get_ext(path_file)).st_size
        tot_send = 0
        with open(ENCRYPTED+get_ext(path_file),'rb') as encrypt:
            while tot_send < tot_dim:
                data = encrypt.read(1024)
                s.send(data)
                tot_send += len(data)

        s.close()

    # apro connessione verso il cracker
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_cracker, port_dest))
    except Exception as e:
        print('errore connessione al cracker')

    else:

        # invio md5 e file criptato
        s.sendall(md5_orig.zfill(32).encode())
        s.sendall(str(pad).encode())
        s.sendall(str(enc_size).zfill(20).encode())

        tot_dim = os.stat(ENCRYPTED + get_ext(path_file)).st_size
        tot_send = 0
        with open(ENCRYPTED + get_ext(path_file), 'rb') as encrypt:
            while tot_send < tot_dim:
                data = encrypt.read(1024)
                s.send(data)
                tot_send += len(data)

        s.close()

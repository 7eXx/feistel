import sys, socket, pcapy, bruteforce
from struct import *

sniff_path = "sniffed_crypted.jpg"
ip_victim = '192.168.55.150'
md5_old = ''
padding = 0
size = 0

if __name__ == '__main__':
    # Sniffo il file
    f = open(sniff_path, "wb")  # OUTPUT
    cap = pcapy.open_live("eth0", 65432, 1, 0)
    print("Listening on %s: net=%s, mask=%s, linktype=%d" % ('eth0', cap.getnet(), cap.getmask(), cap.datalink()))

    byte_read = 0
    size_read = False   #variabile ausiliaria per capire se e' stata ricevuta la lunghezza

    while byte_read < size or not(size_read):
        (header, packet) = cap.next()
        if len(packet) > 0:
            eth_length = 14
            ip_header = packet[eth_length:eth_length + 20]
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            d_addr = socket.inet_ntoa(iph[9])

            if ip_victim == d_addr:

                if iph[6] == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t + 20]
                    tcph = unpack('!HHLLBBHHH', tcp_header)
                    sq = tcph[2]
                    tcph_length = tcph[4] >> 4
                    h_size = t + tcph_length * 4
                    data = packet[h_size:]
                    if ((tcph[1] == 65432) and len(data) > 0):

                        if md5_old == '':       # primo pacchetto
                            md5_old = data.decode()
                            print('md5 sniffato = ', md5_old)

                        elif size == 0:         # secondo pacchetto con struttura padd[1]+size[20]+resto fino a 1448
                            padding = int(data[0:1])
                            print('padding sniffato = ', padding)
                            size = int(data[1:21])
                            size_read = True        # lunghezza letta
                            print('size encrypted = ', size)
                            f.write(data[21:])
                            byte_read += len(data[21:])     # aggiorno il totale di lettura

                        else:
                            f.write(data)
                            byte_read += len(data)      # aggiornamento lettura

                        #print(len(data))
                        #print(data)

    print('Dati Ricevuti tot = ', byte_read)

    total_keys = 2 ** 32
    print("si provano tutte le chiavi da 1 a 2^32 ")
    for i in range(1, total_keys):
        print("Cracking con la chiave %s di %s" % (i, total_keys))

        bruteforce.feistel_decrypter(sniff_path, i, padding)

        # confronto md5 per vedere se ho decifrato correttamente (ergo, ho trovato la chiave)
        md5_new = bruteforce.get_md5(bruteforce.file_dest)
        if md5_new == md5_old:
            print("- Brute Force RIUSCITO!!!!! La chiave è: %s -\n" % i)
            print("File craccato salvato in : " + bruteforce.file_dest)
            break
        else:
            print("- Brute Force fallito con chiave: %s -" % i)

    if i == total_keys:
        print("Spiacente, il Brute force non ha funzionato.. :( ")

import pyshark
from datetime import datetime

captura = pyshark.LiveCapture(interface="wlan0", only_summaries=True)
captura.sniff(packet_count=10)

nome_arquivo = ("dados_sniffer_%s.csv" % (datetime.now()))
arquivo = open(nome_arquivo, "w")
arquivo.write("numero,tempo, origem, destino, protocolo, tamanho, info\n")

for pkt in captura:
	numero = pkt.no
	tempo = pkt.time
	origem = pkt.source
	destino = pkt.destination
	protocolo = pkt.protocol
	tamanho = pkt.length
	info = pkt.info
	arquivo.write("%s,%s,%s,%s,%s,%s,%s\n" % (numero,tempo, origem, destino, protocolo, tamanho, info))

arquivo.close()
captura.close()


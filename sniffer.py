import pyshark
from datetime import datetime
# Estabelece modo LiveCapture com os paramêtros Interface e only_summaries que exibe um resumo das informações obtidas
captura = pyshark.LiveCapture(interface="wlan0", only_summaries=True)

# Inicia sniffer com o limite de 10 pacotes
captura.sniff(packet_count=10)

# Abre arquivo para escrita dos pacotes capturados
nome_arquivo = ("dados_sniffer_%s.csv" % (datetime.now()))
arquivo = open(nome_arquivo, "w")
arquivo.write("numero,tempo, origem, destino, protocolo, tamanho, info\n")

# Filtra informações dos pacotes a serem escritas no arquivo
for pkt in captura:
	numero = pkt.no
	tempo = pkt.time
	origem = pkt.source
	destino = pkt.destination
	protocolo = pkt.protocol
	tamanho = pkt.length
	info = pkt.info
	arquivo.write("%s,%s,%s,%s,%s,%s,%s\n" % (numero,tempo, origem, destino, protocolo, tamanho, info))

# Fecha captura e o arquivo escrito
arquivo.close()
captura.close()


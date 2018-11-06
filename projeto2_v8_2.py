#!/usr/bin/python3
#
# Antes de usar, execute o seguinte comando para evitar que o Linux feche
# as conexões TCP abertas por este programa:
#
# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#
# Retransmissao
# Timout adaptativo

import asyncio
import socket
import struct
import os
import random
import time

FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

MSS = 1460

TESTAR_PERDA_ENVIO = True
K = 4.0
#G = clock granularity ???
G = 1.0
SRTT = 0.0
RTTVAR = 0.0
alpha = 1.0/8.0
beta = 1.0/4.0

enviados = []

class Conexao:
	def __init__(self, id_conexao, seq_no, ack_no):
		self.id_conexao = id_conexao
		self.seq_no = seq_no
		self.ack_no = ack_no
		self.send_base = seq_no
		self.first_ack = True   # significa que o handshake ainda não acabou
		self.timer = None
		self.start_t = 0
		self.end_t = 0
		#timeout adaptativo
		self.RTO = 3.0
		self.last_RTT = 0.0
		self.curr_RTT = 0.0
		#----------------
		self.rwnd = self.cwnd = 2*MSS
		self.rx_win = 1024
		self.ssthresh = self.cwnd
		self.state = "Slow Start"
		self.last_ack = self.send_base #ultimo ack aceito
		self.send_queue = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + 1000000 * b"hello pombo\n"
		self.enviados = []
conexoes = {}



def addr2str(addr):
	return '%d.%d.%d.%d' % tuple(int(x) for x in addr)

def str2addr(addr):
	return bytes(int(x) for x in addr.split('.'))

def handle_ipv4_header(packet):
	version = packet[0] >> 4
	ihl = packet[0] & 0xf
	assert version == 4
	src_addr = addr2str(packet[12:16])
	dst_addr = addr2str(packet[16:20])
	segment = packet[4*ihl:]
	return src_addr, dst_addr, segment


def make_synack(src_port, dst_port, seq_no, ack_no):
	return struct.pack('!HHIIHHHH', src_port, dst_port, seq_no,
					   ack_no, (5<<12)|FLAGS_ACK|FLAGS_SYN,
					   1024, 0, 0)


def calc_checksum(segment):
	if len(segment) % 2 == 1:
		# se for ímpar, faz padding à direita
		segment += b'\x00'
	checksum = 0
	for i in range(0, len(segment), 2):
		x, = struct.unpack('!H', segment[i:i+2])
		checksum += x
		while checksum > 0xffff:
			checksum = (checksum & 0xffff) + 1
	checksum = ~checksum
	return checksum & 0xffff

def fix_checksum(segment, src_addr, dst_addr):
	pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
		struct.pack('!HH', 0x0006, len(segment))
	seg = bytearray(segment)
	seg[16:18] = b'\x00\x00'
	seg[16:18] = struct.pack('!H', calc_checksum(pseudohdr + seg))
	return bytes(seg)


def transmit_as_allowed(fd, conexao):
	print("Sending...")

	tx_win = min(conexao.rwnd, conexao.cwnd)
	amount_to_transmit = max(0, tx_win - len(conexao.enviados))
	data_to_transmit = conexao.send_queue[:amount_to_transmit]
	conexao.send_queue = conexao.send_queue[amount_to_transmit:]
	conexao.enviados.append(data_to_transmit) 

	(dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao
	print(src_addr,src_port)

	for i in range(0, len(data_to_transmit), MSS):
		payload = data_to_transmit[i:i+MSS]

		segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
							  0, (5<<12),
							  1024, 0, 0) + payload

		conexao.seq_no = (conexao.seq_no + len(payload)) & 0xffffffff

		segment = fix_checksum(segment, src_addr, dst_addr)

	if not TESTAR_PERDA_ENVIO or random.random() < 0.95:
		print("Transmit")
		fd.sendto(segment, (dst_addr, dst_port))
	
	# Duvida: Qual a diferenca deste if para o else la embaixo?
	# Ele só entra nesse if quando não tem mais nada para ser transmitido nao eh?
	if conexao.send_queue == b"":
		#print("Verifica necessidade de retrasmissao")
		print("Acabou")
		#So devemos enviar (send_next) depois de receber um ack correto
		asyncio.get_event_loop().call_later(.001, transmit_as_allowed, fd, conexao)
	

	else:
		print("Next")
		asyncio.get_event_loop().call_later(.001, raw_recv, fd)	

	last_ack = conexao.ack_no	   

def raw_recv(fd):
	packet = fd.recv(12000)
	src_addr, dst_addr, segment = handle_ipv4_header(packet)
	src_port, dst_port, seq_no, ack_no, \
		flags, window_size, checksum, urg_ptr = \
		struct.unpack('!HHIIHHHH', segment[:20])
	
	#conta acks duplicados
	dup_ack_cnt = 0

	id_conexao = (src_addr, src_port, dst_addr, dst_port)

	if dst_port != 7000:
		return

	payload = segment[4*(flags>>12):]

	if (flags & FLAGS_SYN) == FLAGS_SYN:
		print('%s:%d -> %s:%d (seq=%d)' % (src_addr, src_port,
										   dst_addr, dst_port, seq_no))

		conexoes[id_conexao] = conexao = Conexao(id_conexao=id_conexao,
												 seq_no=struct.unpack('I', os.urandom(4))[0],
												 ack_no=seq_no + 1)

		fd.sendto(fix_checksum(make_synack(dst_port, src_port, conexao.seq_no, conexao.ack_no),
								   src_addr, dst_addr),
				  (src_addr, src_port))

		conexao.seq_no += 1

	elif id_conexao in conexoes:
		conexao = conexoes[id_conexao]

		if len(payload) > 0:
			# código relacionado a recepção
			if conexao.seq_no == conexao.ack_no:
				conexao.ack_no += len(payload)
				# DONE: envia um ACK para a outra ponta
				fd.sendto(fix_checksum(make_synack(dst_port, src_port, conexao.seq_no,
				 	conexao.ack_no),src_addr, dst_addr),
				  	(src_addr, src_port))

		conexao.seq_no += 1

		if (flags & FLAGS_ACK) == FLAGS_ACK:
			# código relacionado a transmissão
			#Maquina de Estados e Comportamento
			#SLOW START
			if conexao.state == "Slow Start":
				#handshacking
				if conexao.first_ack:
					assert ack_no == conexao.send_base + 1
					conexao.send_base = ack_no
					conexao.first_ack = False
					transmit_as_allowed(fd,conexao)
				#Transicao
				elif conexao.cwnd >= conexao.ssthresh:
						conexao.state = "Congestion Avoidance"
				#NEW ACK no Slow Start
				elif ack_no == conexao.send_base:
					conexao.cwnd = conexao.cwnd + MSS
					conexao.last_ack = ack_no
					dup_ack_cnt = 0
					transmit_as_allowed(fd,conexao)
				#Duplicado
				elif ack_no == conexao.last_ack:
					dup_ack_cnt = dup_ack_cnt + 1
				#3 acks duplicados
				elif dup_ack_cnt == 3:
					conexao.state = "Fast Recovery"
					conexao.ssthresh = conexao.cwnd//2
					cwnd = ssthresh + 3
					# se duplicou 3 vezes tenta retransmitir
					conexao.timer = asyncio.get_event_loop().call_later(conexao.RTO, retransmition, fd, conexao)
				#Timeout ????
				elif ack_no > conexao.send_base:
					#DONE: descartar ack_no - conexao.send_base da fila de enviados
					del enviados[ack_no - conexao.send_base]
					conexao.send_base = ack_no
					if conexao.timer is not None:
						conexao.timer.cancel()
					if len(conexao.enviados) > 0:
						conexao.timer = asyncio.get_event_loop().call_later(conexao.RTO, retransmition, fd, conexao)

			#CONGESTION AVOIDANCE
			if conexao.state == "Congestion Avoidance":
				#NEW ACK no Congestion Avoidance
				if ack_no == conexao.send_base:
					conexao.cwnd = conexao.cwnd + MSS*(MSS//conexao.cwnd)
					conexao.last_ack = ack_no
					dup_ack_cnt = 0
					transmit_as_allowed(fd,conexao)
				#Ack duplicado
				elif ack_no == conexao.last_ack:
					dup_ack_cnt = dup_ack_cnt + 1
				#3 acks duplicados
				elif dup_ack_cnt == 3:
					conexao.state = "Fast Recovery"
					conexao.ssthresh = conexao.cwnd//2
					cwnd = ssthresh + 3
					# se duplicou 3 vezes tenta retransmitir
					conexao.timer = asyncio.get_event_loop().call_later(conexao.RTO, retransmition, fd, conexao)
				#Timeout????
				elif ack_no > conexao.send_base:
					#DONE: descartar ack_no - conexao.send_base da fila de enviados
					del enviados[ack_no - conexao.send_base]
					conexao.send_base = ack_no
					if conexao.timer is not None:
						conexao.timer.cancel()
					if len(conexao.enviados) > 0:
						conexao.timer = asyncio.get_event_loop().call_later(conexao.RTO, retransmition, fd, conexao)

			#FAST RECOVERY
			if conexao.state == "Fast Recovery":
				#tratamento de ack duplicado
				if ack_no == conexao.last_ack:
					conexao.cwnd = conexao.cwnd + MSS
					transmit_as_allowed(fd,conexao)
				#NEW ACK no fast recovery
				elif ack_no == conexao.send_base:
					conexao.cwnd = conexao.ssthresh
					conexao.last_ack = ack_no
					dup_ack_cnt = 0
					conexao.state = "Congestion Avoidance"
				#Timeout ???
				elif ack_no > conexao.send_base:
					#DONE: descartar ack_no - conexao.send_base da fila de enviados
					del enviados[ack_no - conexao.send_base]
					conexao.send_base = ack_no
					if conexao.timer is not None:
						conexao.timer.cancel()
					if len(conexao.enviados) > 0:
						conexao.timer = asyncio.get_event_loop().call_later(conexao.RTO, retransmition, fd, conexao)
			

	else:
		print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
			(src_addr, src_port, dst_addr, dst_port))


#Calcula o RTO da conexao
def RTO(conexao):
	conexao.last_RTT = conexao.curr_RTT
	#como pegar o end_t?
	conxao.curr_RTT = conexao.curr_RTT + conexao.end_t

	#timeout
	#primeira vez
	if conexao.last_RTT == 0.0:
		print("Primeiro RTT")
		SRTT = conexao.curr_RTT  
		RTTVAR = conexao.curr_RTT/2 
		conexao.RTO = SRTT + max(G, K*RTTVAR)
	else:#Se houver um rtt subsequente
	    RTTVAR = (1 - beta)*RTTVAR + beta*abs(SRTT - conexao.curr_RTT)#12.5
	    print("RTTVAR: " + str(RTTVAR))
	    SRTT = (1 - alpha)*SRTT + alpha*conexao.curr_RTT
	    print("SRTT: " + str(SRTT))
	    conexao.RTO = SRTT + max(G, K*RTTVAR)

	    #Corrige os limites do RTO
	    if conexao.RTO < 1.0:
	        conexao.RTO = 1.0
	    if conexao.RTO > 60.0:
	        conexao.RTO = 60.0

def retransmition(fd,conexao):
	(dst_addr, dst_port, src_addr, src_port) = conexao.id_conexao
	print("RETRANSMIT...")

	#Maquina de estados
	if conexao.state == "Slow Start":
		conexao.ssthresh = conexao.cwnd//2
		conexao.cwnd = MSS
		dup_ack_cnt = 0
	elif conexao.state == "Congestion Avoidance":
		conexao.ssthresh = conexao.cwnd//2
		conexao.cwnd = MSS
		dup_ack_cnt = 0	
		conexao.state = "Slow Start"
	elif conexao.state == "Fast Recovery":
		conexao.ssthresh = conexao.cwnd//2
		conexao.cwnd = 1
		dup_ack_cnt = 0
		conexao.state = "Slow Start"

	#TODO: precisa verificar qual pacote dos enviados precisa se retransmitido

	#Está mandando valor 0,0,0, temos que mudar isso
	segment = struct.pack('!HHIIHHHH', src_port, dst_port, conexao.seq_no,
							conexao.ack_no, (5<<12)|FLAGS_FIN|FLAGS_ACK,
						  0, 0, 0)
	segment = fix_checksum(segment, src_addr, dst_addr)
	fd.sendto(segment, (dst_addr, dst_port))


if __name__ == '__main__':
	fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	loop = asyncio.get_event_loop()
	loop.add_reader(fd, raw_recv, fd)
	loop.run_forever()

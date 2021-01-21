# -*- coding: utf-8 -*-

#
# Created: Fri Feb 19 14:16:28 2016
#      by: Gregorio Carazo Maza
#

# -*- coding: utf-8 -*-
from PyQt4 import QtCore, QtGui
from PyQt4 import QtSql
from PyQt4.QtCore import Qt
from Tkinter import *
from struct import *
import sys, sqlite3, threading, time, os.path, binascii, socket, operator, shutil, pcapy, re
from geoip import open_database
from time import gmtime, strftime
from datetime import datetime, date, timedelta
from operator import itemgetter
import matplotlib.pyplot as plt
import numpy as np
import netifaces as ni

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class updateTableClass(QtCore.QObject):
    updateTableConnection = QtCore.pyqtSignal(int)
    updateTableMessage = QtCore.pyqtSignal(int)
    updateTablePacket = QtCore.pyqtSignal(int)

    updateTableConnectionActivate = True
    updateTableMessageActivate = True
    updateTablePacketActivate = True

    def updateTableConnectionFunction(self):
        if self.updateTableConnectionActivate:
                self.updateTableConnection.emit(1)

    def updateTableMessageFunction(self):
        if self.updateTableMessageActivate:
                self.updateTableMessage.emit(1)

    def updateTablePacketFunction(self):
        if self.updateTablePacketActivate:
                self.updateTablePacket.emit(1)

class errorAnalyst(QtCore.QObject):
    error = QtCore.pyqtSignal(str)

    def errorFunction(self, errorString):
        self.error.emit(errorString)

class Analyst(threading.Thread):
    #updateTable use to update table connection in the GUI

    def __init__(self, pathDataBase, namedataBase, pathOfFilePacket, updateTable, deviceSelected, error, charToRoute):
        super(Analyst, self).__init__()
        self.setName("Analyst")
        self.dataBase = pathDataBase + namedataBase
        self.updateTable = updateTable
        self.addPortConnect = True
        self.device = deviceSelected
        self.pathDataOfPacket = pathDataOfPacket
        self.is_alive = True
        self.charToRoute = charToRoute
        dataBaseConnection = sqlite3.connect(self.dataBase, 10000)
        cursorDataBase = dataBaseConnection.cursor()
        # Initialice new id for next element in table connection
        cursorDataBase.execute('SELECT "id Directory" FROM connection ORDER BY rowid DESC LIMIT 1')
        try:
             self.nextIdConnectionDirectory = cursorDataBase.fetchone()[0] + 1
        except TypeError:
            self.nextIdConnectionDirectory = 1
        # Initialice new id for next element in table message
        cursorDataBase.execute('SELECT "id file or directory" FROM message ORDER BY rowid DESC LIMIT 1')
        try:
            self.nextIdMessageDirectoryFile = cursorDataBase.fetchone()[0] + 1
        except TypeError:
            self.nextIdMessageDirectoryFile = 1
        # Initialice new id for next element in table packet
        cursorDataBase.execute('SELECT "id File" FROM packet ORDER BY rowid DESC LIMIT 1')
        try:
            self.nextIdPacketFile = cursorDataBase.fetchone()[0] + 1
        except TypeError:
            self.nextIdPacketFile = 1
        cursorDataBase.close()
        self.numberPacketReceive = 0
        self.numberDangerousPacket = 0
        self.numberDangerousPacketTCP = 0
        self.numberDangerousPacketICMP = 0
        self.numberDangerousPacketUDP = 0
        self.numberPacketTCP = 0
        self.numberPacketICMP = 0
        self.numberPacketUDP = 0
        self.nonPacket = 0
        self.error = error
        pathFileGeoip = os.path.abspath('config.txt')
        pathFileGeoip = pathFileGeoip.replace("config.txt","")
        if os.path.isfile(pathFileGeoip + self.charToRoute +"GeoLite2-City.mmdb"):
            self.dbIP = open_database(pathFileGeoip + self.charToRoute + "GeoLite2-City.mmdb")
        else:
            self.dbIP = ""

    def changeDevice(self, deviceSelected):
        self.device = deviceSelected

    def stopSniffer(self):
        self.is_alive = False

    def ethAddr(self, a):
      address = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
      return address

    def restoreStringOfMessage(self, idMessage, idConnection, politicFragmentation, listPacket, idMessageFile):
        if(politicFragmentation == "DSDB"):
            pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(idConnection) + self.charToRoute + "idDirectoryMessage-" + str(idMessageFile) + self.charToRoute + "idFileMessage-" + str(idMessageFile) + ".txt"
            fileData = open(pathofPacketFile, 'w+')
            shiftAccumulate = 0
            for value in range(len(listPacket)):
                packet = listPacket[value]
                if os.path.isfile(packet[6]):
                    filePacket = open(packet[6], 'r')
                    if shiftAccumulate == packet[2]:
                        numBlockBits = packet[5]/64
                        if (packet[5]%64) != 0:
                            numBlockBits += 1
                        shiftAccumulate += numBlockBits * 64
                        fileData.write(filePacket.read().rstrip('\n'))
                    else:
                        if listPacket[value - 1][2] < packet[2]:
                            numBlockBits = packet[5]/64
                            if (packet[5]%64) != 0:
                                numBlockBits += 1
                            filePacket.seek((shiftAccumulate - packet[2])/8)
                            fileData.write(filePacket.read((packet[5] - (shiftAccumulate - packet[2]))/8).rstrip('\n'))
                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                        else:
                            # no tiene sentido que el offset del paquete sea menor que el anterior de la lista porque
                            # estos elementos se ordenan en funcion del offset
                            datePacket0 = datetime.strptime(listPacket[value - 1][4], "%Y-%m-%d %H:%M:%S")
                            datePacket1 = datetime.strptime(packet[4], "%Y-%m-%d %H:%M:%S")
                            if(datePacket0 >= datePacket1):
                                fileData.seek((shiftAccumulate - packet[2])/8)
                                fileData.write(filePacket.read((packet[5] - (shiftAccumulate - packet[2]))/8).rstrip('\n'))
                                numBlockBits = packet[5]/64
                                if (packet[5]%64) != 0:
                                    numBlockBits += 1
                                shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                            else:
                                fileData.seek((packet[5] - (shiftAccumulate - packet[2]))/8, 2)
                                fileData.write(filePacket.read().rstrip('\n'))
                                numBlockBits = packet[5]/64
                                if (packet[5]%64) != 0:
                                    numBlockBits += 1
                                shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                    filePacket.close()
            fileData.close()
            valueUpdate = [(pathofPacketFile, idMessage)]
            self.cursorDataBase.executemany('UPDATE message SET "Path file of string" = ? WHERE rowid = ?', valueUpdate)
        elif(politicFragmentation == "Linux"):
            pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(idConnection) + self.charToRoute + "idDirectoryMessage-" + str(idMessageFile) + self.charToRoute + "idFileMessage-" + str(idMessageFile) + ".txt"
            fileData = open(pathofPacketFile, 'w')
            fileData.close()
            fileData = open(pathofPacketFile, 'w+')
            shiftAccumulate = 0
            for value in range(len(listPacket)):
                packet = listPacket[value]
                if os.path.isfile(packet[6]):
                    filePacket = open(packet[6], 'r')
                    if shiftAccumulate == packet[2]:
                        numBlockBits = packet[5]/64
                        if (packet[5]%64) != 0:
                            numBlockBits += 1
                        shiftAccumulate += numBlockBits * 64
                        fileData.write(filePacket.read().rstrip('\n'))
                    else:
                        datePacket0 = datetime.strptime(listPacket[value - 1][4], "%Y-%m-%d %H:%M:%S")
                        datePacket1 = datetime.strptime(packet[4], "%Y-%m-%d %H:%M:%S")
                        if(datePacket0 >= datePacket1):
                            fileData.read((shiftAccumulate - packet[2])/8)
                            fileData.write(filePacket.read((packet[5] - (shiftAccumulate - packet[2]))/8).rstrip('\n'))
                            if (packet[5]%64) != 0:
                                numBlockBits += 1
                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                        else:
                            fileData.seek((packet[5] - (shiftAccumulate - packet[2]))/8, 2)
                            fileData.write(filePacket.read().rstrip('\n'))
                            if (packet[5]%64) != 0:
                                numBlockBits += 1
                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                    filePacket.close()
            fileData.close()
            valueUpdate = [(pathofPacketFile, idMessage)]
            self.cursorDataBase.executemany('UPDATE message SET "Path file of string" = ? WHERE rowid = ?', valueUpdate)
        elif(politicFragmentation == "Firts"):
            pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(idConnection) + self.charToRoute + "idDirectoryMessage-" + str(idMessageFile) + self.charToRoute + "idFileMessage-" + str(idMessageFile) + ".txt"
            fileData = open(pathofPacketFile, 'w')
            fileData.close()
            fileData = open(pathofPacketFile, 'w+')
            shiftAccumulate = 0
            for value in range(len(listPacket)):
                packet = listPacket[value]
                if os.path.isfile(packet[6]):
                    filePacket = open(packet[6], 'r')
                    if shiftAccumulate == packet[2]:
                        numBlockBits = packet[5]/64
                        if (packet[5]%64) != 0:
                            numBlockBits += 1
                        shiftAccumulate += numBlockBits * 64
                        fileData.write(filePacket.read().rstrip('\n'))
                    else:
                        datePacket0 = datetime.strptime(listPacket[value - 1][4], "%Y-%m-%d %H:%M:%S")
                        datePacket1 = datetime.strptime(packet[4], "%Y-%m-%d %H:%M:%S")
                        if(datePacket0 <= datePacket1):
                            fileData.read((shiftAccumulate - packet[2])/8)
                            fileData.write(filePacket.read((packet[5] - (shiftAccumulate - packet[2]))/8).rstrip('\n'))
                            if (packet[5]%64) != 0:
                                numBlockBits += 1
                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                        else:
                            fileData.seek((packet[5] - (shiftAccumulate - packet[2]))/8, 2)
                            fileData.write(filePacket.read().rstrip('\n'))
                            if (packet[5]%64) != 0:
                                numBlockBits += 1
                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                    filePacket.close()
            fileData.close()
            valueUpdate = [(pathofPacketFile, idMessage)]
            self.cursorDataBase.executemany('UPDATE message SET "Path file of string" = ? WHERE rowid = ?', valueUpdate)
        self.dataBaseConnection.commit()
        self.updateTable.updateTableMessageFunction()

    def checkNumber(self, decNumber):
        # we make the number have 4 digit in hexadecimal
        number = decNumber
        while number > 65535:
            auxiliar = number >> 16
            number = (number & 0xFFFF) + auxiliar
        return number

    def saveAttack(self, description, typeAttack, sourceAddr, destinationAddr, sourcePort, destinationPort, sourceMac, destinationMac, idFragmentation, flagsFragment,
                      positionFragment, ttl, dataSize, metric, data, packetSave):
        # this function include all which you need to detect RST attack
        dataSelect = [str(sourceAddr), str(destinationAddr), str(sourcePort), str(destinationPort), "TCP"]
        self.cursorDataBase.execute('SELECT rowid, Description, "Type Attack", "id Directory" FROM connection WHERE "IP Source" LIKE ? AND "IP Destination" LIKE ?'
                               'AND "Port Source" LIKE ? AND "Port Destination" LIKE ? AND "Type Traffic" LIKE ?', dataSelect)
        connection = self.cursorDataBase.fetchall()
        if not len(connection): # if this first packet of connection, we create new connection in data base
            # location = self.dbIP.lookup(sourceAddr)
            # if location != None:
            #     country = location.country
            #     timeZone = location.timezone
            # else:
            #     country = ""
            #     timeZone = ""
            country = "Spain"
            timeZone = "Spain/Jaen"
            connectionData = [(str(sourceAddr), str(sourcePort), str(sourceMac), str(destinationAddr), str(destinationPort), str(destinationMac), "TCP", typeAttack, country, timeZone, strftime("%Y-%m-%d %H:%M:%S", gmtime()), description,self.nextIdConnectionDirectory)]
            self.cursorDataBase.executemany('INSERT INTO connection VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)', connectionData)
            if not os.path.isdir(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(self.nextIdConnectionDirectory)):
                os.makedirs(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(self.nextIdConnectionDirectory))
            self.nextIdConnectionDirectory += 1
            # self.dataBaseConnection.commit()
            self.cursorDataBase.execute('SELECT rowid, Description, "Type Attack", "id Directory" FROM connection WHERE rowid = (SELECT MAX(rowid) FROM connection)')
            connection = self.cursorDataBase.fetchall()
        else:
            # if this connection exists then we update description of this connection
            descriptionConnection = str(connection[0][1]) + description
            if typeAttack != "":
                valueUpdate = [(descriptionConnection, connection[0][2] | typeAttack, connection[0][0])]
            else:
                valueUpdate = [(descriptionConnection, connection[0][2], connection[0][0])]
            self.cursorDataBase.executemany('UPDATE connection SET "Description" = ?, "Type Attack" = ? WHERE rowid = ?', valueUpdate)
            # self.dataBaseConnection.commit()

        if (flagsFragment == 1 or positionFragment != 0) and packetSave == False: # if it is true this packet is fragment
            # we have to check that this packet is a part of message that it exist
            self.cursorDataBase.execute('SELECT rowid, "id file or directory" FROM message WHERE "id connection" = ? AND Fragment = 1 AND "id fragmentation" = ?', (connection[0][0],idFragmentation))
            try: # if this sentence do an error then this is a firts packet of this connection
                idMessage = self.cursorDataBase.fetchone()[0]
                idDirectoryFileMessage = self.cursorDataBase.fetchone()[1]
            except TypeError:
                idDirectoryFileMessage = self.nextIdMessageDirectoryFile
                # we create directory to save this packet only this is a first packet
                if not os.path.isdir(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(idDirectoryFileMessage)):
                    os.makedirs(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(idDirectoryFileMessage))
                # create new message in message's table
                self.cursorDataBase.execute('SELECT "Politic Fragmentation" FROM routingTable WHERE "Destination Address" LIKE ? AND Metric = ?', (destinationAddr, metric))
                self.nextIdMessageDirectoryFile += 1
                try:
                    politicFragmentation = str(self.cursorDataBase.fetchone()[0])
                except TypeError:
                    politicFragmentation = "DSDB"
                message = [(connection[0][0], str(idFragmentation), 1, politicFragmentation, strftime("%Y-%m-%d %H:%M:%S", gmtime()), -1, "", idDirectoryFileMessage)]
                self.cursorDataBase.executemany("INSERT INTO message VALUES (?,?,?,?,?,?,?,?)", message)
                self.dataBaseConnection.commit()
                self.cursorDataBase.execute('SELECT rowid FROM message WHERE rowid = (SELECT MAX(rowid) FROM message)')
                idMessage = self.cursorDataBase.fetchone()[0]

            # Initialize value of packet and create data file of this packet
            pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(idDirectoryFileMessage) + self.charToRoute + "idPacket" + str(self.nextIdPacketFile) + ".txt"
            packet = [(connection[0][0], idMessage, positionFragment, ttl, strftime("%Y-%m-%d %H:%M:%S", gmtime()), dataSize, pathofPacketFile, self.nextIdPacketFile)]
            self.cursorDataBase.executemany('INSERT INTO packet VALUES (?,?,?,?,?,?,?,?)', packet)
            fileData = open(pathofPacketFile, 'w')
            fileData.write(data)
            fileData.close()
            # self.dataBaseConnection.commit()
            self.nextIdPacketFile += 1
        else: # If this message is not fragment, we create new file to write data of message
            if packetSave == False:
                pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(self.nextIdMessageDirectoryFile) + self.charToRoute + "idFileMessage-" + str(self.nextIdMessageDirectoryFile) + ".txt"
                if not os.path.isdir(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(self.nextIdMessageDirectoryFile)):
                    os.makedirs(self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(connection[0][3]) + self.charToRoute + "idDirectoryMessage-" + str(self.nextIdMessageDirectoryFile))
                if len(data) == 0:
                    message = [(connection[0][0], idFragmentation, 0, "None", strftime("%Y-%m-%d %H:%M:%S", gmtime()), dataSize, "this packet don't have anything", self.nextIdMessageDirectoryFile)]
                else:
                    message = [(connection[0][0], idFragmentation, 0, "None", strftime("%Y-%m-%d %H:%M:%S", gmtime()), dataSize, str(pathofPacketFile), self.nextIdMessageDirectoryFile)]
                    fileData = open(pathofPacketFile, 'w')
                    fileData.write(data)
                    fileData.close()
                self.cursorDataBase.executemany("INSERT INTO message VALUES (?,?,?,?,?,?,?,?)", message)
                # self.dataBaseConnection.commit()
                self.nextIdMessageDirectoryFile += 1
        self.dataBaseConnection.commit()
        self.updateTable.updateTableConnectionFunction()
        self.updateTable.updateTableMessageFunction()
        self.updateTable.updateTablePacketFunction()

    def run(self):
        # 65536
        cap = pcapy.open_live(self.device , 65536 , 1 , 0)
        self.dataBaseConnection = sqlite3.connect(self.dataBase, 10000)
        self.cursorDataBase = self.dataBaseConnection.cursor()
        myIP = ""
        try:
            ni.ifaddresses(self.device)
            myIP = ni.ifaddresses(self.device)[2][0]['addr']
        except ValueError:
            print "Device " + self.device + " is not connecting"
            self.is_alive = False

        # Analyst wait to receive data of sniffer
        dateStart =  strftime("%Y-%m-%d %H:%M:%S", gmtime())
        while self.is_alive != False:
            (header, packet) = cap.next()
            time.sleep(0.0001)
            if packet != "":
                self.nonPacket = 0
                self.numberPacketReceive += 1
                # print ('%s: captured %d bytes, truncated to %d bytes' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), header.getlen(), header.getcaplen()))
                #parse ethernet header
                ethLength = 14

                ethHeader = packet[0:ethLength]
                eth = unpack('!6s6sH' , ethHeader)
                ethProtocol = socket.ntohs(eth[2])
                destinationMac = self.ethAddr(packet[0:6])
                sourceMac = self.ethAddr(packet[6:12])

                #Parse IP packets, IP Protocol number = 8
                if ethProtocol == 8 :
                    packetSave = False
                    #Parse IP header
                    #take first 20 characters for the ip header
                    ipHeader = packet[ethLength:20+ethLength]

                    #now unpack them :)
                    iph = unpack('!BBHHHBBH4s4s' , ipHeader)

                    versionIhl = iph[0]
                    version = versionIhl >> 4
                    ihl = versionIhl & 0xF

                    iphLength = ihl * 4
                    idFragmentation = iph[3]
                    flagsFragment = iph[4] >> 13
                    positionFragment = ((iph[4] | 0xE000) ^ 0xE000) * 64
                    ttl = iph[5]
                    protocol = iph[6]
                    checksumIP = iph[7]
                    sourceAddr = socket.inet_ntoa(iph[8]);
                    destinationAddr = socket.inet_ntoa(iph[9]);

                    #TCP protocol
                    if protocol == 6 :
                        self.numberPacketTCP += 1
                        t = iphLength + ethLength
                        tcpHeader = packet[t:t+20]

                        #now unpack them :)
                        tcph = unpack('!HHLLBBHHH' , tcpHeader)

                        doffReserved = tcph[4]
                        tcphLength = (doffReserved >> 4) * 4
                        if tcphLength > 20:
                            lengthAcumulate = 20
                            stringOfUnpack = '!HHLLBBHHH'
                            while lengthAcumulate < tcphLength:
                                if lengthAcumulate + 2 <= tcphLength:
                                    stringOfUnpack = stringOfUnpack + 'H'
                                    lengthAcumulate += 2
                                elif lengthAcumulate + 1 == tcphLength:
                                    stringOfUnpack = stringOfUnpack + 'B'
                                    lengthAcumulate += 1
                            # if tcpLength is more than 20 so we should upack again
                            tcpHeader = packet[t:t+lengthAcumulate]
                            tcph = unpack(stringOfUnpack , tcpHeader)

                        sourcePort = tcph[0]
                        destinationPort = tcph[1]
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        flagsTCP = tcph[5]

                        hSize = ethLength + iphLength + tcphLength

                        #get data from the packet
                        data = packet[hSize:]
                        dataSize = len(data.encode("hex")) * 8

                        # Manipulacion del paquete
                        # flagsTCP = 4
                        # ttl = 4
                        # flagsFragment = 0
                        # positionFragment = 376
                        # destinationAddr = "192.168.100.198"
                        # dataSize = 192
                        # idFragmentation = 47488
                        # destinationPort = 8080
                        # sourcePort = 8080
                        # sourceAddr = "192.168.100.101"
                        # data = " proyecto terminado"

                        self.cursorDataBase.execute('SELECT Metric FROM routingTable WHERE "Destination Address" LIKE ?', (destinationAddr,))
                        try:
                            metric = int(self.cursorDataBase.fetchone()[0])
                        except TypeError:
                            metric = 0
                        if metric > ttl: # we should to check if packet has the same ttl which we need to arrive
                            # it is attack of ttl
                            # ttl attack can't do without a message that it doesn't be fragment
                            description = " this packet is a ttl attack"
                            self.saveAttack(description, 1, sourceAddr, destinationAddr, sourcePort, destinationPort, sourceMac, destinationMac, idFragmentation, flagsFragment, positionFragment, ttl, dataSize, metric, data, packetSave)
                            self.numberDangerousPacket += 1
                            self.numberDangerousPacketTCP += 1
                            packetSave = True

                        # we check if this packet is a attack with RST bit tcph[4]
                        if ((flagsTCP | 0xFB) ^ 0xFB) == 4:
                            # now we should check checksum to know if it is a attack
                            seudoHeaderIP = iph[6]
                            sourceAddrAuxiliar = int(binascii.hexlify(socket.inet_aton(sourceAddr)), 16)
                            seudoHeaderIP += (sourceAddrAuxiliar >> 16) + (sourceAddrAuxiliar & 0xFFFF)
                            destinationAddrAuxiliar = int(binascii.hexlify(socket.inet_aton(destinationAddr)), 16)
                            seudoHeaderIP += (destinationAddrAuxiliar >> 16) + (destinationAddrAuxiliar & 0xFFFF)
                            seudoHeaderIP += tcphLength + dataSize
                            seudoHeaderIP = self.checkNumber(seudoHeaderIP)
                            #  calculate checksum tcp header
                            checksumTCPCalculate = tcph[0]
                            checksumTCPCalculate += tcph[1]
                            checksumTCPCalculate += (tcph[2] >> 16) + (tcph[2] & 0xFFFF)
                            checksumTCPCalculate += (tcph[3] >> 16) + (tcph[3] & 0xFFFF)
                            checksumTCPCalculate += ((tcph[4] << 8) + tcph[5])
                            checksumTCPCalculate += tcph[6]
                            checksumTCPCalculate += tcph[8]
                            if tcphLength > 20:
                                for i in range(9, len(tcph)):
                                    checksumTCPCalculate += tcph[i]
                            checksumTCPCalculate = self.checkNumber(checksumTCPCalculate)
                            if data != "":
                                dataInt = data.encode("hex")
                                dataInt = int(dataInt, 16)
                                dataInt = self.checkNumber(dataInt)
                            else:
                                dataInt = 0
                            checksumTCPCalculate += seudoHeaderIP + dataInt
                            checksumTCPCalculate = self.checkNumber(checksumTCPCalculate)
                            checksumTCPCalculate = operator.invert(checksumTCPCalculate)
                            checksumTCPCalculate = checksumTCPCalculate & 0xFFFF
                            # now we check if checksumTCPCalculate != checksum of packet, if it happens then it is RST attack
                            if checksumTCPCalculate != tcph[6]:
                                # however RST is activate and ttl is < then it is attack of RST
                                description = " this connection have a RST attack"
                                self.saveAttack(description, 2, sourceAddr, destinationAddr, sourcePort, destinationPort, sourceMac, destinationMac, idFragmentation, flagsFragment, positionFragment, ttl, dataSize, metric, data, packetSave)
                                self.numberDangerousPacket += 1
                                self.numberDangerousPacketTCP += 1
                                packetSave = True

                        #  we check checksum if SYN Bit is activate
                        if ((flagsTCP | 0xFD) ^ 0xFD) == 2:
                            # now we should check checksum to know if it is a attack
                            seudoHeaderIP = iph[6]
                            sourceAddrAuxiliar = int(binascii.hexlify(socket.inet_aton(sourceAddr)), 16)
                            seudoHeaderIP += (sourceAddrAuxiliar >> 16) + (sourceAddrAuxiliar & 0xFFFF)
                            destinationAddrAuxiliar = int(binascii.hexlify(socket.inet_aton(destinationAddr)), 16)
                            seudoHeaderIP += (destinationAddrAuxiliar >> 16) + (destinationAddrAuxiliar & 0xFFFF)
                            seudoHeaderIP += tcphLength + dataSize
                            seudoHeaderIP = self.checkNumber(seudoHeaderIP)
                            #  calculate checksum tcp header
                            checksumTCPCalculate = tcph[0]
                            checksumTCPCalculate += tcph[1]
                            checksumTCPCalculate += (tcph[2] >> 16) + (tcph[2] & 0xFFFF)
                            checksumTCPCalculate += (tcph[3] >> 16) + (tcph[3] & 0xFFFF)
                            checksumTCPCalculate += ((tcph[4] << 8) + tcph[5])
                            checksumTCPCalculate += tcph[6]
                            checksumTCPCalculate += tcph[8]
                            if tcphLength > 20:
                                for i in range(9, len(tcph)):
                                    checksumTCPCalculate += tcph[i]
                            checksumTCPCalculate = self.checkNumber(checksumTCPCalculate)
                            if data != "":
                                dataInt = data.encode("hex")
                                dataInt = int(dataInt, 16)
                                dataInt = self.checkNumber(dataInt)
                            else:
                                dataInt = 0
                            checksumTCPCalculate += seudoHeaderIP + dataInt
                            checksumTCPCalculate = self.checkNumber(checksumTCPCalculate)
                            checksumTCPCalculate = operator.invert(checksumTCPCalculate)
                            checksumTCPCalculate = checksumTCPCalculate & 0xFFFF
                            # now we check if checksumTCPCalculate != checksum of packet, if it happens then it is SYN attack
                            if checksumTCPCalculate != tcph[6]:
                                description = " this connection have a SYN attack"
                                self.saveAttack(description, 4, sourceAddr, destinationAddr, sourcePort, destinationPort, sourceMac, destinationMac, idFragmentation, flagsFragment, positionFragment, ttl, dataSize, metric, data, packetSave)
                                self.numberDangerousPacket += 1
                                self.numberDangerousPacketTCP += 1
                                packetSave = True

                        # Now we check if all packet are restore unless we should restore
                        if flagsFragment == 1 or positionFragment != 0:
                            self.cursorDataBase.execute('SELECT rowid, "id connection", "Politic Fragmentation", "id file or directory" FROM message WHERE "id fragmentation" = ?', (idFragmentation,))
                            dataMessage = self.cursorDataBase.fetchall()
                            if len(dataMessage) != 0:
                                self.cursorDataBase.execute('SELECT "id Directory" FROM connection WHERE rowid = ?', (dataMessage[0][1],))
                                idDirectoryConnection = self.cursorDataBase.fetchone()[0]
                                # Like this connection exist then we should save this packet and check if this message is complete
                                pathofPacketFile = self.pathDataOfPacket + self.charToRoute + "idDirectory-" + str(idDirectoryConnection) + self.charToRoute + "idDirectoryMessage-" + str(dataMessage[0][3]) + self.charToRoute + "idPacket" + str(self.nextIdPacketFile) + ".txt"
                                fileData = open(pathofPacketFile, 'w')
                                fileData.write(data)
                                fileData.close()
                                packet = [(dataMessage[0][1], dataMessage[0][0], positionFragment, ttl, strftime("%Y-%m-%d %H:%M:%S", gmtime()), dataSize, pathofPacketFile, self.nextIdPacketFile)]
                                self.cursorDataBase.executemany('INSERT INTO packet VALUES (?,?,?,?,?,?,?,?)', packet)
                                self.nextIdPacketFile += 1
                                self.cursorDataBase.execute('SELECT * FROM packet WHERE "id message" = ?', (dataMessage[0][0],))
                                try:
                                    dataPacket = self.cursorDataBase.fetchall()
                                except TypeError:
                                    print "Don't have packet that this is fragment"
                                    break
                                listPacket = sorted(dataPacket, key=itemgetter(2))
                                allPacketArrive = True
                                attackWithFragmentation = False
                                shiftAccumulate = 0
                                if listPacket[0][2] == 0:
                                    for value in range(len(listPacket)):
                                        packet = listPacket[value]
                                        if shiftAccumulate == packet[2]:
                                            numBlockBits = packet[5]/64
                                            if (packet[5]%64) != 0:
                                                numBlockBits += 1
                                            shiftAccumulate += numBlockBits * 64
                                        elif shiftAccumulate > packet[2]:
                                            numBlockBits = packet[5]/64
                                            if (packet[5]%64) != 0:
                                                numBlockBits += 1
                                            shiftAccumulate += ((numBlockBits * 64) - (shiftAccumulate - packet[2]))
                                            attackWithFragmentation = True
                                        else:
                                            allPacketArrive = False
                                            break
                                    if allPacketArrive == True:
                                        # if this condition is true then all packet of this message have arrived and we restore message
                                        self.restoreStringOfMessage(dataMessage[0][0],dataMessage[0][1], dataMessage[0][2], listPacket, dataMessage[0][3])
                                        valueUpdate = [(shiftAccumulate, dataMessage[0][0])]
                                        self.cursorDataBase.executemany('UPDATE message SET "Size" = ? WHERE rowid = ?', valueUpdate)
                                        if attackWithFragmentation == True:
                                            self.cursorDataBase.execute('SELECT Description, "Type Attack" FROM connection WHERE rowid = ?', (dataMessage[0][1],))
                                            connection = self.cursorDataBase.fetchall()
                                            descriptionConnection = connection[0][0] + " In this connection we have been detected an attack with Fragmentation"
                                            valueUpdate = [(descriptionConnection, connection[0][1] | 8, dataMessage[0][1])]
                                            self.cursorDataBase.executemany('UPDATE connection SET "Description" = ?, "Type Attack" = ? WHERE rowid = ?', valueUpdate)
                                            self.numberDangerousPacket += 1
                                            self.numberDangerousPacketTCP += 1
                            else:
                                self.saveAttack("", 0, sourceAddr, destinationAddr, sourcePort, destinationPort, sourceMac, destinationMac, idFragmentation, flagsFragment, positionFragment, ttl, dataSize, metric, data, packetSave)
                                packetSave = True

                    #ICMP Packets
                    elif protocol == 1 :
                        self.numberPacketICMP += 1
                        u = iphLength + ethLength
                        icmphLength = 4
                        icmpHeader = packet[u:u+4]

                        #now unpack them :)
                        icmph = unpack('!BBH' , icmpHeader)

                        icmpType = icmph[0]
                        code = icmph[1]
                        checksum = icmph[2]

                        hSize = ethLength + iphLength + icmphLength
                        dataSize = len(packet) - hSize

                        #get data from the packet
                        data = packet[hSize:]

                    #UDP packets
                    elif protocol == 17 :
                        self.numberPacketUDP += 1
                        u = iphLength + ethLength
                        udphLength = 8
                        udp_header = packet[u:u+8]

                        #now unpack them :)
                        udph = unpack('!HHHH' , udp_header)

                        sourcePort = udph[0]
                        destinationPort = udph[1]
                        length = udph[2]
                        checksum = udph[3]

                        hSize = ethLength + iphLength + udphLength
                        dataSize = len(packet) - hSize

                        #get data from the packet
                        data = packet[hSize:]
        if myIP != "":
            dateFinish =  strftime("%Y-%m-%d %H:%M:%S", gmtime())
            value = [(self.numberPacketReceive, self.numberDangerousPacket, dateStart, dateFinish, self.numberDangerousPacketTCP, self.numberDangerousPacketICMP, self.numberDangerousPacketUDP, self.numberPacketTCP, self.numberPacketICMP, self.numberPacketUDP)]
            self.cursorDataBase.executemany('INSERT INTO information VALUES (?,?,?,?,?,?,?,?,?,?)', value)
        self.dataBaseConnection.commit()
        self.dataBaseConnection.close()
        print "Exit of analyst"

class Cleaner(threading.Thread):
    def __init__(self, updateTable, dataBase, pathFile, charToRoute):
        super(Cleaner, self).__init__()
        self.setName("Cleaner")
        self.updateTable = updateTable
        self.dataBase = dataBase
        self.dateSelect = ""
        self.pathFile = pathFile
        self.executed = False
        self.charToRoute = charToRoute

    def changeDate(self, value):
        self.dateSelect = str(value)

    def run(self):
        self.executed = True
        self.connectionDataBase = sqlite3.connect(self.dataBase, 10000)
        self.cursorDataBase = self.connectionDataBase.cursor()

        self.cursorDataBase.execute('SELECT rowid, "id Directory" FROM connection WHERE strftime("%Y-%m-%d %H:%M:%S", "Date") <= strftime("%Y-%m-%d %H:%M:%S", ?)', (self.dateSelect,))
        data = self.cursorDataBase.fetchall()
        for i in range(len(data)):
            if os.path.isdir(self.pathFile +self.charToRoute + "idDirectory-" + str(data[i][1])):
                shutil.rmtree(self.pathFile + self.charToRoute + "idDirectory-" + str(data[i][1]))
            self.cursorDataBase.execute('DELETE FROM packet WHERE "id connection" = ?', (data[i][0],))
            self.cursorDataBase.execute('DELETE FROM message WHERE "id connection" = ?', (data[i][0],))
            self.cursorDataBase.execute('DELETE FROM connection WHERE rowid = ?', (data[i][0],))

        self.cursorDataBase.execute("VACUUM")
        self.connectionDataBase.commit()
        self.connectionDataBase.close()
        self.updateTable.updateTableConnectionFunction()
        self.updateTable.updateTableMessageFunction()
        self.updateTable.updateTablePacketFunction()
        self.executed = False

class jDialogInsertDate(QtCore.QObject):
    signalDateToCleaner = QtCore.pyqtSignal(str)

    def setupUi(self, Dialog, dateSelect):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(675, 169)
        Dialog.setMinimumSize(QtCore.QSize(675, 169))
        Dialog.setMaximumSize(QtCore.QSize(675, 169))
        Dialog.setFocusPolicy(QtCore.Qt.NoFocus)
        Dialog.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedKingdom))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(30, 30, 631, 17))
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayoutWidget = QtGui.QWidget(Dialog)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(30, 120, 631, 41))
        self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.cancelButton = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.cancelButton.setObjectName(_fromUtf8("cancelButton"))
        self.horizontalLayout.addWidget(self.cancelButton)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.acceptButton = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.acceptButton.setObjectName(_fromUtf8("acceptButton"))
        self.horizontalLayout.addWidget(self.acceptButton)
        self.dateEditLine = QtGui.QLineEdit(Dialog)
        self.dateEditLine.setGeometry(QtCore.QRect(30, 70, 621, 27))
        self.dateEditLine.setObjectName(_fromUtf8("dateEditLine"))
        self.dateEditLine.setPlaceholderText(dateSelect)
        self.dateSelect = dateSelect

        QtCore.QObject.connect(self.acceptButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.acceptButton_clicked)
        QtCore.QObject.connect(self.cancelButton, QtCore.SIGNAL(_fromUtf8("clicked()")), Dialog.reject)
        QtCore.QObject.connect(self.dateEditLine, QtCore.SIGNAL(_fromUtf8("returnPressed()")), self.acceptButton.click)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Dialog", None))
        self.label.setText(_translate("Dialog", "Insert erase deadline with this format: YYYY-MM-DD HH:mm:ss, example: 2016-02-04 13:00:00", None))
        self.cancelButton.setText(_translate("Dialog", "Cancel", None))
        self.acceptButton.setText(_translate("Dialog", "Accept", None))

    def acceptButton_clicked(self):
        valueString = self.dateEditLine.text()
        formatDate = re.compile('....-..-.. ..:..:..')
        if formatDate.match(valueString) is not None:
            if valueString != '':
                self.signalDateToCleaner.emit(valueString)
                self.cancelButton.click()
            else:
                self.signalDateToCleaner.emit(self.dateSelect)
                self.cancelButton.click()
        else:
            error = "Date doesn't have the format, please you should insert again"
            dialogError = QtGui.QDialog()
            dialogError.ui = jDialogError()
            dialogError.ui.setupUi(dialogError, error, "Error")
            dialogError.exec_()

class jDialogHelp(QtCore.QObject):

    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(932, 614)
        Dialog.setMinimumSize(QtCore.QSize(932, 614))
        Dialog.setMaximumSize(QtCore.QSize(932, 614))
        Dialog.setFocusPolicy(QtCore.Qt.NoFocus)
        Dialog.setLocale(QtCore.QLocale(QtCore.QLocale.English, QtCore.QLocale.UnitedKingdom))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.tabWidget = QtGui.QTabWidget(Dialog)
        self.tabWidget.setGeometry(QtCore.QRect(0, 40, 921, 531))
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab = QtGui.QWidget()
        self.tab.setObjectName(_fromUtf8("tab"))
        self.label_49 = QtGui.QLabel(self.tab)
        self.label_49.setGeometry(QtCore.QRect(10, 40, 901, 17))
        self.label_49.setObjectName(_fromUtf8("label_49"))
        self.label_50 = QtGui.QLabel(self.tab)
        self.label_50.setGeometry(QtCore.QRect(10, 60, 901, 17))
        self.label_50.setObjectName(_fromUtf8("label_50"))
        self.label_5 = QtGui.QLabel(self.tab)
        self.label_5.setGeometry(QtCore.QRect(10, 10, 901, 17))
        self.label_5.setObjectName(_fromUtf8("label_5"))
        self.label_13 = QtGui.QLabel(self.tab)
        self.label_13.setGeometry(QtCore.QRect(10, 100, 901, 17))
        self.label_13.setObjectName(_fromUtf8("label_13"))
        self.label_16 = QtGui.QLabel(self.tab)
        self.label_16.setGeometry(QtCore.QRect(10, 120, 901, 17))
        self.label_16.setObjectName(_fromUtf8("label_16"))
        self.tabWidget.addTab(self.tab, _fromUtf8(""))
        self.tableCTab = QtGui.QWidget()
        self.tableCTab.setObjectName(_fromUtf8("tableCTab"))
        self.scrollArea = QtGui.QScrollArea(self.tableCTab)
        self.scrollArea.setGeometry(QtCore.QRect(0, 0, 921, 501))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName(_fromUtf8("scrollArea"))
        self.scrollAreaWidgetContents = QtGui.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 919, 499))
        self.scrollAreaWidgetContents.setObjectName(_fromUtf8("scrollAreaWidgetContents"))
        self.label_3 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_3.setGeometry(QtCore.QRect(10, 30, 901, 17))
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.label_7 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_7.setGeometry(QtCore.QRect(10, 10, 891, 17))
        self.label_7.setObjectName(_fromUtf8("label_7"))
        self.label_11 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_11.setGeometry(QtCore.QRect(10, 240, 901, 17))
        self.label_11.setObjectName(_fromUtf8("label_11"))
        self.label_8 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_8.setGeometry(QtCore.QRect(10, 150, 901, 17))
        self.label_8.setObjectName(_fromUtf8("label_8"))
        self.label_9 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_9.setGeometry(QtCore.QRect(10, 220, 901, 17))
        self.label_9.setObjectName(_fromUtf8("label_9"))
        self.label_10 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_10.setGeometry(QtCore.QRect(10, 170, 901, 17))
        self.label_10.setObjectName(_fromUtf8("label_10"))
        self.label_4 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_4.setGeometry(QtCore.QRect(10, 200, 901, 17))
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.label_21 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_21.setGeometry(QtCore.QRect(10, 50, 901, 17))
        self.label_21.setObjectName(_fromUtf8("label_21"))
        self.label_23 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_23.setGeometry(QtCore.QRect(10, 80, 901, 17))
        self.label_23.setObjectName(_fromUtf8("label_23"))
        self.label_24 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_24.setGeometry(QtCore.QRect(10, 100, 901, 17))
        self.label_24.setObjectName(_fromUtf8("label_24"))
        self.label_22 = QtGui.QLabel(self.scrollAreaWidgetContents)
        self.label_22.setGeometry(QtCore.QRect(10, 290, 901, 17))
        self.label_22.setObjectName(_fromUtf8("label_22"))
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.tabWidget.addTab(self.tableCTab, _fromUtf8(""))
        self.tableMTab = QtGui.QWidget()
        self.tableMTab.setObjectName(_fromUtf8("tableMTab"))
        self.scrollArea_2 = QtGui.QScrollArea(self.tableMTab)
        self.scrollArea_2.setGeometry(QtCore.QRect(0, 0, 921, 501))
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName(_fromUtf8("scrollArea_2"))
        self.scrollAreaWidgetContents_2 = QtGui.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 919, 499))
        self.scrollAreaWidgetContents_2.setObjectName(_fromUtf8("scrollAreaWidgetContents_2"))
        self.label_6 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_6.setGeometry(QtCore.QRect(10, 30, 901, 17))
        self.label_6.setObjectName(_fromUtf8("label_6"))
        self.label_12 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_12.setGeometry(QtCore.QRect(10, 10, 891, 17))
        self.label_12.setObjectName(_fromUtf8("label_12"))
        self.label_14 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_14.setGeometry(QtCore.QRect(10, 150, 901, 17))
        self.label_14.setObjectName(_fromUtf8("label_14"))
        self.label_25 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_25.setGeometry(QtCore.QRect(10, 60, 901, 17))
        self.label_25.setObjectName(_fromUtf8("label_25"))
        self.label_51 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_51.setGeometry(QtCore.QRect(10, 90, 901, 17))
        self.label_51.setObjectName(_fromUtf8("label_51"))
        self.label_52 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_52.setGeometry(QtCore.QRect(10, 120, 901, 17))
        self.label_52.setObjectName(_fromUtf8("label_52"))
        self.label_18 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_18.setGeometry(QtCore.QRect(10, 170, 901, 17))
        self.label_18.setObjectName(_fromUtf8("label_18"))
        self.label_19 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_19.setGeometry(QtCore.QRect(10, 200, 901, 17))
        self.label_19.setObjectName(_fromUtf8("label_19"))
        self.label_20 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_20.setGeometry(QtCore.QRect(10, 260, 901, 17))
        self.label_20.setObjectName(_fromUtf8("label_20"))
        self.label_53 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_53.setGeometry(QtCore.QRect(10, 310, 901, 17))
        self.label_53.setObjectName(_fromUtf8("label_53"))
        self.label_54 = QtGui.QLabel(self.scrollAreaWidgetContents_2)
        self.label_54.setGeometry(QtCore.QRect(10, 230, 901, 17))
        self.label_54.setObjectName(_fromUtf8("label_54"))
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents_2)
        self.tabWidget.addTab(self.tableMTab, _fromUtf8(""))
        self.label_15 = QtGui.QLabel(Dialog)
        self.label_15.setGeometry(QtCore.QRect(0, 10, 901, 17))
        self.label_15.setObjectName(_fromUtf8("label_15"))
        self.pushButton = QtGui.QPushButton(Dialog)
        self.pushButton.setGeometry(QtCore.QRect(820, 580, 98, 27))
        self.pushButton.setObjectName(_fromUtf8("pushButton"))

        self.retranslateUi(Dialog)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QObject.connect(self.pushButton, QtCore.SIGNAL(_fromUtf8("clicked()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        self.label_49.setText(_translate("Dialog", "Type  attack that this program detect: TTL, RST, SYN and Fragmentation, this field is codificate with a", None))
        self.label_50.setText(_translate("Dialog", "number that if you pass it to binary, you can see type attack.", None))
        self.label_5.setText(_translate("Dialog", "Warning!!,  when you click to \"start sniffing\" this can generate lag, because the sniffer is using a lot of resources.", None))
        self.label_13.setText(_translate("Dialog", "When you click in some device, only  will can sniff one device, and if you  can make out one or two device, you should execute with", None))
        self.label_16.setText(_translate("Dialog", "admin permission.", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Dialog", "Generally", None))
        self.label_3.setText(_translate("Dialog", "If you double-click on this table, you will can see all message this connection and if you click rigth button of mouse , you can stop update", None))
        self.label_7.setText(_translate("Dialog", "Table Connection: This table show all connections that it classify as dangerous.", None))
        self.label_11.setText(_translate("Dialog", " if you click right button,  you can stop update this table or clear filter to show all message.", None))
        self.label_8.setText(_translate("Dialog", "Table Message: This table show all message, if this message is fragmented, so this generate a lot of row in table packet, and if we have", None))
        self.label_9.setText(_translate("Dialog", "all packet of this message , then we can restore message and we can show content of these, but it isn\'t fragment so you can see content", None))
        self.label_10.setText(_translate("Dialog", "of this packet.", None))
        self.label_4.setText(_translate("Dialog", "If you double-click on this table, you will can see all packet of this message or you can see content of this and like in connection table,", None))
        self.label_21.setText(_translate("Dialog", "this table.", None))
        self.label_23.setText(_translate("Dialog", "How can you know that attack type is this connection? well this table has a column that this can see type attack, but it is a number, if you", None))
        self.label_24.setText(_translate("Dialog", "pass this number to binary (5 in binary is 0101)  you can see that this is a attack of TTL and SYN.", None))
        self.label_22.setText(_translate("Dialog", "Table Packet: This table use the same as message table but with packet instead of message.", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tableCTab), _translate("Dialog", "Tables", None))
        self.label_6.setText(_translate("Dialog", "In menu you can see two list of button: File and Graphics.", None))
        self.label_12.setText(_translate("Dialog", "Button of menu:", None))
        self.label_14.setText(_translate("Dialog", "Insert routing table: This options you can edit routing table of sniffer, for sniffer will can detect a TTL attack.", None))
        self.label_25.setText(_translate("Dialog", "In File, you can choose between Start sniffing, Select device, Insert routing table, Edit config file, Clear data base and Exit.", None))
        self.label_51.setText(_translate("Dialog", "Start Sniffing: When you click here, you start sniffing and process of capture all dangerous packet.", None))
        self.label_52.setText(_translate("Dialog", "Select device: Here you can choose between all device of network to sniffing.", None))
        self.label_18.setText(_translate("Dialog", "Warning!!! routing table of sniffer must be the same as routing table of router", None))
        self.label_19.setText(_translate("Dialog", "Edit config file: in this option you can edit the config of sniffer.  PLEASE!!!!  you should respect format of this file.", None))
        self.label_20.setText(_translate("Dialog", "Clear data base: this option use to clear data base, When you click this program ask a date to delete all rows smaller than date inserted", None))
        self.label_53.setText(_translate("Dialog", "In graphics, you can choose between different graphics, when you click in one, you can see graphics.", None))
        self.label_54.setText(_translate("Dialog", "Activate system updateTable: It allow to activate system, you should activate when the UI is lagging, default is active", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tableMTab), _translate("Dialog", "Button of menu", None))
        self.label_15.setText(_translate("Dialog", "Select options about you want know more.", None))
        self.pushButton.setText(_translate("Dialog", "Exit", None))

class jDialogSelectDevice(QtCore.QObject):
    signalDeviceSelected = QtCore.pyqtSignal(list)

    def setupUi(self, Dialog, device):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(338, 342)
        Dialog.setMinimumSize(QtCore.QSize(338, 342))
        Dialog.setMaximumSize(QtCore.QSize(338, 342))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(20, 10, 291, 17))
        self.label.setObjectName(_fromUtf8("label"))
        self.acceptButton = QtGui.QPushButton(Dialog)
        self.acceptButton.setGeometry(QtCore.QRect(220, 300, 98, 27))
        self.acceptButton.setObjectName(_fromUtf8("pushButton"))
        self.cancelButton = QtGui.QPushButton(Dialog)
        self.cancelButton.setGeometry(QtCore.QRect(10, 300, 98, 27))
        self.cancelButton.setObjectName(_fromUtf8("pushButton_2"))
        self.scrollArea = QtGui.QScrollArea(Dialog)
        self.scrollArea.setGeometry(QtCore.QRect(20, 30, 301, 251))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName(_fromUtf8("scrollArea"))
        self.scrollAreaWidgetContents = QtGui.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 299, 249))
        self.scrollAreaWidgetContents.setObjectName(_fromUtf8("scrollAreaWidgetContents"))
        self.listCheckBox = list()
        for i in range(len(device)):
            self.listCheckBox.append(QtGui.QCheckBox(self.scrollAreaWidgetContents))
            self.listCheckBox[i].setGeometry(QtCore.QRect(10, 10 + (i * 20), 241, 22))
            self.listCheckBox[i].setObjectName(_fromUtf8("checkBox"))
            self.listCheckBox[i].setText(_translate("Dialog", str(device[i]), None))
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)

        QtCore.QObject.connect(self.acceptButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.buttonAccept_clicked)
        QtCore.QObject.connect(self.cancelButton, QtCore.SIGNAL(_fromUtf8("clicked()")), self.buttonCancel_clicked)
        QtCore.QObject.connect(self.cancelButton, QtCore.SIGNAL(_fromUtf8("closeWindow()")), Dialog.reject)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Select device", None))
        self.label.setText(_translate("Dialog", "Select device that you want to sniff:", None))
        self.acceptButton.setText(_translate("Dialog", "Accept", None))
        self.cancelButton.setText(_translate("Dialog", "Cancel", None))

    def buttonAccept_clicked(self):
        deviceSelected = list()
        for i in range(len(self.listCheckBox)):
            if self.listCheckBox[i].isChecked():
                deviceSelected.append(self.listCheckBox[i].text())
        self.signalDeviceSelected.emit(deviceSelected)
        self.cancelButton.emit(QtCore.SIGNAL(_fromUtf8("closeWindow()")))

    def buttonCancel_clicked(self):
        device = list()
        device.append("")
        self.signalDeviceSelected.emit(device)
        self.cancelButton.emit(QtCore.SIGNAL(_fromUtf8("closeWindow()")))

class jDialogTableRoute(QtCore.QObject):

    def setupUi(self, Dialog, dataBase):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(622, 425)
        Dialog.setMinimumSize(QtCore.QSize(622, 425))
        Dialog.setMaximumSize(QtCore.QSize(622, 425))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(20, 20, 571, 17))
        self.label.setObjectName(_fromUtf8("label"))
        self.horizontalLayoutWidget = QtGui.QWidget(Dialog)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(410, 369, 191, 51))
        self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))
        self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.buttonCancel = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.buttonCancel.setObjectName(_fromUtf8("buttonCancel"))
        self.horizontalLayout.addWidget(self.buttonCancel)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.buttonSave = QtGui.QPushButton(self.horizontalLayoutWidget)
        self.buttonSave.setObjectName(_fromUtf8("buttonSave"))
        self.horizontalLayout.addWidget(self.buttonSave)

        self.modelRoutingTable = QtSql.QSqlTableModel(Dialog)
        self.modelRoutingTable.setTable("routingTable")
        self.modelRoutingTable.setEditStrategy(QtSql.QSqlTableModel.OnManualSubmit)
        self.modelRoutingTable.select()
        self.tableRouting = QtGui.QTableView(Dialog)
        self.tableRouting.setGeometry(QtCore.QRect(10, 50, 591, 311))
        self.tableRouting.setWhatsThis(_fromUtf8(""))
        self.tableRouting.setStyleSheet(_fromUtf8(""))
        self.tableRouting.setModel(self.modelRoutingTable)
        self.tableRouting.resizeColumnsToContents()

        self.horizontalLayoutWidget_2 = QtGui.QWidget(Dialog)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(10, 370, 194, 51))
        self.horizontalLayoutWidget_2.setObjectName(_fromUtf8("horizontalLayoutWidget_2"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_2.setMargin(0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        self.buttonDelete = QtGui.QPushButton(self.horizontalLayoutWidget_2)
        self.buttonDelete.setObjectName(_fromUtf8("buttonDelete"))
        self.horizontalLayout_2.addWidget(self.buttonDelete)
        self.buttonInsert = QtGui.QPushButton(self.horizontalLayoutWidget_2)
        self.buttonInsert.setObjectName(_fromUtf8("buttonInsert"))
        self.horizontalLayout_2.addWidget(self.buttonInsert)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

        # Event
        QtCore.QObject.connect(self.buttonSave, QtCore.SIGNAL(_fromUtf8("clicked()")), self.clickedSaveButton)
        QtCore.QObject.connect(self.buttonSave, QtCore.SIGNAL(_fromUtf8("saveAndExit()")), Dialog.reject)
        QtCore.QObject.connect(self.buttonCancel, QtCore.SIGNAL(_fromUtf8("clicked()")), Dialog.reject)
        QtCore.QObject.connect(self.buttonInsert, QtCore.SIGNAL(_fromUtf8("clicked()")), self.clickedInsertButton)
        QtCore.QObject.connect(self.buttonDelete, QtCore.SIGNAL(_fromUtf8("clicked()")), self.clickedDeleteButton)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Insert Routing Table", None))
        self.label.setText(_translate("Dialog", "Insert routing table of the route:", None))
        self.buttonCancel.setText(_translate("Dialog", "Cancel", None))
        self.buttonSave.setText(_translate("Dialog", "Save", None))
        self.buttonDelete.setText(_translate("Dialog", "Delete Row", None))
        self.buttonInsert.setText(_translate("Dialog", "Insert row", None))

    def clickedSaveButton(self):
        self.modelRoutingTable.submitAll()
        self.buttonSave.emit(QtCore.SIGNAL(_fromUtf8("saveAndExit()")))

    def clickedDeleteButton(self):

        idOfRowDelete = self.tableRouting.currentIndex().row()

        for row in range(idOfRowDelete, self.modelRoutingTable.rowCount()):
            indexRowSelected = self.modelRoutingTable.index(row, 0)

            idRow = self.tableRouting.model().data(indexRowSelected).toString()
            newIdRow = QtCore.QVariant(int(idRow) - 1)
            self.modelRoutingTable.setData(indexRowSelected, newIdRow)

        self.modelRoutingTable.removeRow(self.tableRouting.currentIndex().row())
        self.modelRoutingTable.submitAll()

    def clickedInsertButton(self):
        # Insert new row under the last row
        indexOfInsert = self.modelRoutingTable.rowCount()
        self.modelRoutingTable.insertRow(indexOfInsert)

        # indexOfFirtsColumnLastRow, we are allowed to access to firts column of last row
        self.tableRouting.selectRow(indexOfInsert - 1)
        indexOfFirtsColumnLastRow = self.modelRoutingTable.index(indexOfInsert - 1, 0)

        idOfLastRow = self.tableRouting.model().data(indexOfFirtsColumnLastRow).toString()

        idNewRow = QtCore.QVariant(int(idOfLastRow) + 1)
        indexOfNewRow = self.modelRoutingTable.index(indexOfInsert, 0)
        self.modelRoutingTable.setData(indexOfNewRow, idNewRow)
        self.modelRoutingTable.submitAll()

class jDialogConfig(QtCore.QObject):
    changeConfig = QtCore.pyqtSignal(list)

    def setupUi(self, Dialog, pathFile, mode):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        Dialog.resize(550, 450)
        Dialog.setMinimumSize(QtCore.QSize(550, 450))
        Dialog.setMaximumSize(QtCore.QSize(550, 450))
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(10, 410, 531, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.contentFileConfig = QtGui.QTextEdit(Dialog)
        self.contentFileConfig.setGeometry(QtCore.QRect(10, 110, 531, 291))
        self.contentFileConfig.setObjectName(_fromUtf8("contentFileConfig"))

        # Read file
        self.pathFile = pathFile
        file = open(pathFile+'config.txt','r')
        line = file.read()
        file.close()
        if line.find("nameDataBase = '") >= 0:
            self.contentFileConfig.setText(line)
        else:
            self.contentFileConfig.setEnabled(False)
            self.contentFileConfig.setText("No se encontro el fichero")

        self.pathFileConfigLineEdit = QtGui.QLineEdit(Dialog)
        self.pathFileConfigLineEdit.setGeometry(QtCore.QRect(10, 40, 431, 27))
        self.pathFileConfigLineEdit.setObjectName(_fromUtf8("pathFileConfig"))
        self.pathFileConfigLineEdit.setText(pathFile+"config.txt")
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(10, 10, 431, 17))
        self.label.setObjectName(_fromUtf8("label"))
        self.label_2 = QtGui.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(10, 80, 421, 17))
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.retranslateUi(Dialog)

        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), self.buttonAccept_clicked)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), self.buttonCancel_clicked)
        # this signal use to close window but without exit of program
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("cancelOrSave()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        # mode use to know who execute this dialog, if this has been executed for MainWindow then it doesn't have close this program
        self.mode = mode

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "File configure", None))
        self.label.setText(_translate("Dialog", "Address of  file confing:", None))
        self.label_2.setText(_translate("Dialog", "Content of  file confing:", None))

    def buttonAccept_clicked(self):
        if self.mode == "initial":
            fileConfig = open(self.pathFile + 'config.txt', 'w')
            fileConfig.write(self.contentFileConfig.toPlainText())
            fileConfig.close()

            self.buttonBox.emit(QtCore.SIGNAL(_fromUtf8("cancelOrSave()")))
        else :
            changeField = list()
            fileConfig = open(self.pathFile + 'configAuxiliary.txt', 'w')
            fileConfig.write(self.contentFileConfig.toPlainText())
            fileConfig.close()

            # send change of file config
            fileConfig = open(self.pathFile +'configAuxiliary.txt','r')
            nameDataBase = fileConfig.readline()
            pathDataBase = fileConfig.readline()
            pathDataOfPacket = fileConfig.readline()
            fileConfig.close()
            os.remove(self.pathFile +'configAuxiliary.txt')

            nameDataBase = nameDataBase.replace("nameDataBase = '", "")
            nameDataBase = nameDataBase.replace("'","")
            nameDataBase = nameDataBase.replace("\n","")
            changeField.append(nameDataBase)
            pathDataBase = pathDataBase.replace("pathDataBase = '", "")
            pathDataBase = pathDataBase.replace("'", "")
            pathDataBase = pathDataBase.replace("\n", "")
            changeField.append(pathDataBase)
            pathDataOfPacket = pathDataOfPacket.replace("pathDataOfPacket = '", "")
            pathDataOfPacket = pathDataOfPacket.replace("'", "")
            pathDataOfPacket = pathDataOfPacket.replace("\n", "")
            changeField.append(pathDataOfPacket)

            self.changeConfig.emit(changeField)
            self.buttonBox.emit(QtCore.SIGNAL(_fromUtf8("cancelOrSave()")))

    def buttonCancel_clicked(self):
        if self.mode == "initial":
            os.remove(self.pathFile + "config.txt")
            sys.exit(0)
        else:
            self.buttonBox.emit(QtCore.SIGNAL(_fromUtf8("cancelOrSave()")))

class jDialogData(QtCore.QObject):

    def setupUi(self, Dialog, pathOfFile):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(536, 531)
        Dialog.setMinimumSize(QtCore.QSize(536, 531))
        Dialog.setMaximumSize(QtCore.QSize(536, 531))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(10, 490, 521, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.textEditData = QtGui.QTextEdit(Dialog)
        self.textEditData.setGeometry(QtCore.QRect(10, 40, 511, 441))
        self.textEditData.setObjectName(_fromUtf8("textEditData"))
        file = open(pathOfFile, "r")
        self.textEditData.setText(file.read())
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(15, 10, 221, 20))
        self.label.setObjectName(_fromUtf8("label"))

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), Dialog.reject)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Show data of message", None))
        self.label.setText(_translate("Dialog", "Data of packet:", None))

class jDialogError(QtCore.QObject):
    def setupUi(self, Dialog, error, typeError):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize((len(error) * 7) + 38, 122)
        Dialog.setMinimumSize(QtCore.QSize((len(error) * 7) + 38, 122))
        Dialog.setMaximumSize(QtCore.QSize((len(error) * 7) + 38, 122))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.ButtonClose = QtGui.QPushButton(Dialog)
        self.ButtonClose.setGeometry(QtCore.QRect((len(error) * 7) - 109, 80, 98, 27))
        self.ButtonClose.setObjectName(_fromUtf8("ButtonClose"))
        self.error = QtGui.QLabel(Dialog)
        self.error.setGeometry(QtCore.QRect(30, 16, len(error) * 7, 21))
        self.error.setText(_fromUtf8(error))
        self.error.setObjectName(_fromUtf8("error"))
        self.typeError = typeError

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.ButtonClose, QtCore.SIGNAL(_fromUtf8("clicked()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", self.typeError, None))
        self.ButtonClose.setText(_translate("Dialog", "Close", None))

class jDialogActivateUpdateTable(QtCore.QObject):
    activateUpdateTableSytem = QtCore.pyqtSignal(bool)

    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(404, 110)
        Dialog.resize(404, 110)
        Dialog.setMinimumSize(QtCore.QSize(404, 110))
        Dialog.setMaximumSize(QtCore.QSize(404, 110))
        Dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.buttonBox = QtGui.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(10, 60, 381, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtGui.QDialogButtonBox.Cancel|QtGui.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName(_fromUtf8("buttonBox"))
        self.label = QtGui.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(10, 10, 371, 17))
        self.label.setObjectName(_fromUtf8("label"))

        self.retranslateUi(Dialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("accepted()")), self.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("rejected()")), self.cancel)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL(_fromUtf8("exit()")), Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(_translate("Dialog", "Activate update table", None))
        self.label.setText(_translate("Dialog", "Do you want to activate updateTable system?", None))

    def accept(self):
        self.activateUpdateTableSytem.emit(True)
        self.buttonBox.emit(QtCore.SIGNAL(_fromUtf8("exit()")))

    def cancel(self):
        self.activateUpdateTableSytem.emit(False)
        self.buttonBox.emit(QtCore.SIGNAL(_fromUtf8("exit()")))

class Proyecto_MainWindows(QtGui.QDialog):

    def setupUi(self, MainWindow, nameDataBase, pathDataBase, pathDataOfPacket, db, charToRoute):
        # code generate with pyqt
        MainWindow.setObjectName(_fromUtf8("Proyecto"))
        MainWindow.resize(1024, 700)
        MainWindow.setMinimumSize(QtCore.QSize(1024, 700))
        MainWindow.setMaximumSize(QtCore.QSize(1024, 700))
        MainWindow.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        MainWindow.setWindowModality(QtCore.Qt.ApplicationModal)
        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.db = db
        # model create to synchronise with table "connection" of data base
        self.modelListConnections = QtSql.QSqlTableModel(self.centralwidget)
        self.modelListConnections.setTable("connection")
        self.modelListConnections.setEditStrategy(QtSql.QSqlTableModel.OnFieldChange)
        self.modelListConnections.select()
        self.listConnections = QtGui.QTableView(self.centralwidget)
        self.listConnections.setGeometry(QtCore.QRect(0, 0, 1021, 261))
        self.listConnections.setWhatsThis(_fromUtf8(""))
        self.listConnections.setStyleSheet(_fromUtf8(""))
        self.listConnections.setModel(self.modelListConnections)
        self.listConnections.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        # self.listConnections.resizeColumnsToContents()
        self.listConnections.resizeColumnToContents(0)
        self.listConnections.resizeColumnToContents(1)
        self.listConnections.resizeColumnToContents(2)
        self.listConnections.resizeColumnToContents(3)
        self.listConnections.resizeColumnToContents(4)
        self.listConnections.resizeColumnToContents(5)
        self.listConnections.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        # self.modelListConnections.
        # Here, I have defined what happen when anybody do double click and the contextual menu of listConnections
        self.listConnections.doubleClicked.connect(self.actionSelectRow_doubleClicked_connection)
        self.listConnections.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listConnections.customContextMenuRequested.connect(self.contextMenuListConnection)
        # create context menu of List Packets
        self.actionStopRefreshPopMenuListConnections = QtGui.QAction('Stop refresh', self)
        self.popMenuListConnection = QtGui.QMenu(self)
        self.popMenuListConnection.addAction(self.actionStopRefreshPopMenuListConnections)

        # the same that listPacket here we create a model to synchronise table with table "message" of data base
        self.modelDetailMessage = QtSql.QSqlTableModel(self.centralwidget)
        self.modelDetailMessage.setTable("message")
        self.modelDetailMessage.select()
        self.modelDetailMessage.setEditStrategy(QtSql.QSqlTableModel.OnManualSubmit)
        self.listMessage = QtGui.QTableView(self.centralwidget)
        self.listMessage.setGeometry(QtCore.QRect(0, 260, 1024, 192))
        self.listMessage.setObjectName(_fromUtf8("listMessage"))
        self.listMessage.setModel(self.modelDetailMessage)
        self.listMessage.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.listMessage.resizeColumnsToContents()
        self.listMessage.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.listMessage.doubleClicked.connect(self.actionSelectRow_doubleClicked_message)
        self.listMessage.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listMessage.customContextMenuRequested.connect(self.contextMenuListMessage)
        self.actionStopRefreshPopMenuListMessage = QtGui.QAction('Stop refresh', self)
        self.actionClearFilterPopMenuListMessage = QtGui.QAction('Clear filter', self)
        self.popMenuListMessage = QtGui.QMenu(self)
        self.popMenuListMessage.addAction(self.actionStopRefreshPopMenuListMessage)
        self.popMenuListMessage.addAction(self.actionClearFilterPopMenuListMessage)

        # the same that others
        self.modelListPacket = QtSql.QSqlTableModel(self.centralwidget)
        self.modelListPacket.setTable("packet")
        self.modelListPacket.select()
        self.modelListPacket.setEditStrategy(QtSql.QSqlTableModel.OnManualSubmit)
        self.listPacket = QtGui.QTableView(self.centralwidget)
        self.listPacket.setGeometry(QtCore.QRect(0, 451, 1024, 212))
        self.listPacket.setObjectName(_fromUtf8("ListPacket"))
        self.listPacket.setModel(self.modelListPacket)
        self.listPacket.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.listPacket.resizeColumnsToContents()
        self.listPacket.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        self.listPacket.doubleClicked.connect(self.actionSelectRow_doubleClicked_packet)
        self.listPacket.setContextMenuPolicy(Qt.CustomContextMenu)
        self.listPacket.customContextMenuRequested.connect(self.contextMenuListPacket)
        self.actionStopRefreshPopMenuListPacket = QtGui.QAction('Stop refresh', self)
        self.actionClearFilterPopMenuListPacket = QtGui.QAction('Clear filter', self)
        self.popMenuListPacket = QtGui.QMenu(self)
        self.popMenuListPacket.addAction(self.actionStopRefreshPopMenuListPacket)
        self.popMenuListPacket.addAction(self.actionClearFilterPopMenuListPacket)

        # Code generate by pyqt
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtGui.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1024, 25))
        self.menubar.setObjectName(_fromUtf8("menubar"))
        self.menuFile = QtGui.QMenu(self.menubar)
        self.menuFile.setObjectName(_fromUtf8("menuFile"))
        self.menuGraphics = QtGui.QMenu(self.menubar)
        self.menuGraphics.setObjectName(_fromUtf8("menuGraphics"))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)
        self.actionStart = QtGui.QAction(MainWindow)
        self.actionStart.setObjectName(_fromUtf8("actionStart"))
        self.actionSelectDevice = QtGui.QAction(MainWindow)
        self.actionSelectDevice.setCheckable(False)
        self.actionSelectDevice.setObjectName(_fromUtf8("actionSelectDevice"))
        self.actionInsertTableRoute = QtGui.QAction(MainWindow)
        self.actionInsertTableRoute.setCheckable(False)
        self.actionInsertTableRoute.setObjectName(_fromUtf8("actionInsertTableRoute"))
        self.actionConfigDataBase = QtGui.QAction(MainWindow)
        self.actionConfigDataBase.setObjectName(_fromUtf8("actionConfigDataBase"))
        self.actionSystemUpdateTable = QtGui.QAction(MainWindow)
        self.actionSystemUpdateTable.setObjectName(_fromUtf8("actionActivateSystemUpdateTable"))
        self.actionClearDB = QtGui.QAction(MainWindow)
        self.actionClearDB.setObjectName(_fromUtf8("actionClearDB"))
        self.actionExit = QtGui.QAction(MainWindow)
        self.actionExit.setObjectName(_fromUtf8("actionExit"))
        self.menuFile.addAction(self.actionStart)
        self.menuFile.addAction(self.actionSelectDevice)
        self.menuFile.addAction(self.actionInsertTableRoute)
        self.menuFile.addAction(self.actionConfigDataBase)
        self.menuFile.addAction(self.actionSystemUpdateTable)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionClearDB)
        self.menuFile.addSeparator()
        self.menuFile.addAction(self.actionExit)
        self.menubar.addAction(self.menuFile.menuAction())
        self.actionFirtsGraphics = QtGui.QAction(MainWindow)
        self.actionFirtsGraphics.setObjectName(_fromUtf8("actionFirts_Graphics"))
        self.actionSecondGraphics = QtGui.QAction(MainWindow)
        self.actionSecondGraphics.setObjectName(_fromUtf8("actionSecond_Graphics"))
        self.actionThirdGraphics = QtGui.QAction(MainWindow)
        self.actionThirdGraphics.setObjectName(_fromUtf8("actionThird_Graphics"))
        self.actionFourthGraphics = QtGui.QAction(MainWindow)
        self.actionFourthGraphics.setObjectName(_fromUtf8("actionFourth_Graphics"))
        self.actionFiveGraphics = QtGui.QAction(MainWindow)
        self.actionFiveGraphics.setObjectName(_fromUtf8("actionFourth_Graphics"))
        self.actionSixGraphics = QtGui.QAction(MainWindow)
        self.actionSixGraphics.setObjectName(_fromUtf8("actionSix_Graphics"))
        self.actionHelp = QtGui.QAction(MainWindow)
        self.actionHelp.setObjectName(_fromUtf8("actionHelp"))
        self.menuGraphics.addAction(self.actionFirtsGraphics)
        self.menuGraphics.addAction(self.actionSecondGraphics)
        self.menuGraphics.addAction(self.actionThirdGraphics)
        self.menuGraphics.addAction(self.actionFourthGraphics)
        self.menuGraphics.addSeparator()
        self.menuGraphics.addAction(self.actionFiveGraphics)
        self.menuGraphics.addAction(self.actionSixGraphics)
        self.menubar.addAction(self.menuGraphics.menuAction())
        self.menubar.addAction(self.actionHelp)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # define data of GUI
        self.deviceSelected = list()
        self.deviceSelected.append("")
        self.pathDataBase = pathDataBase
        self.nameDataBase = nameDataBase
        self.pathDataOfPacket = pathDataOfPacket
        self.charToRoute = charToRoute
        # date and number updatetable use to update table depending on time and number of times updated
        self.lastDateUpdateTable = 0
        self.limitUpdateTable = 0
        self.numberUpdateTable = 0
        self.activateSystemUpdateTable = True

        # Code to programming answer to action of users
        QtCore.QObject.connect(self.actionStart, QtCore.SIGNAL("triggered()"), self.actionStart_clicked)
        QtCore.QObject.connect(self.actionSelectDevice, QtCore.SIGNAL("triggered()"), self.actionSelectDevice_clicked)
        QtCore.QObject.connect(self.actionInsertTableRoute, QtCore.SIGNAL("triggered()"), self.actionInsertTableRoute_clicked)
        QtCore.QObject.connect(self.actionExit, QtCore.SIGNAL("triggered()"), self.shutDown)
        QtCore.QObject.connect(self.actionStopRefreshPopMenuListConnections, QtCore.SIGNAL("triggered()"), self.actionStopRefreshPopMenuListConnection_clicked)
        QtCore.QObject.connect(self.actionStopRefreshPopMenuListMessage, QtCore.SIGNAL("triggered()"), self.actionStopRefreshPopMenuListMessage_clicked)
        QtCore.QObject.connect(self.actionStopRefreshPopMenuListPacket, QtCore.SIGNAL("triggered()"), self.actionStopRefreshPopMenuListPacket_clicked)
        QtCore.QObject.connect(self.actionClearFilterPopMenuListMessage, QtCore.SIGNAL("triggered()"), self.actionClearFilterPopMenuListMessage_clicked)
        QtCore.QObject.connect(self.actionClearFilterPopMenuListPacket, QtCore.SIGNAL("triggered()"), self.actionClearFilterPopMenuListPacket_clicked)
        QtCore.QObject.connect(self.actionConfigDataBase, QtCore.SIGNAL("triggered()"), self.actionConfigDataBase_clicked)
        QtCore.QObject.connect(self.actionSystemUpdateTable, QtCore.SIGNAL("triggered()"), self.actionActivateSystemUpdateTable_clicked)
        QtCore.QObject.connect(self.actionFirtsGraphics, QtCore.SIGNAL("triggered()"), self.actionFirtsGraphics_clicked)
        QtCore.QObject.connect(self.actionSecondGraphics, QtCore.SIGNAL("triggered()"), self.actionSecondGraphics_clicked)
        QtCore.QObject.connect(self.actionThirdGraphics, QtCore.SIGNAL("triggered()"), self.actionThirdGraphics_clicked)
        QtCore.QObject.connect(self.actionFourthGraphics, QtCore.SIGNAL("triggered()"), self.actionFourthGraphics_clicked)
        QtCore.QObject.connect(self.actionFiveGraphics, QtCore.SIGNAL("triggered()"), self.actionFiveGraphics_clicked)
        QtCore.QObject.connect(self.actionSixGraphics, QtCore.SIGNAL("triggered()"), self.actionSixGraphics_clicked)
        QtCore.QObject.connect(self.actionHelp, QtCore.SIGNAL("triggered()"), self.actionHelp_clicked)
        QtCore.QObject.connect(self.actionClearDB, QtCore.SIGNAL("triggered()"), self.actionClearDB_clicked)
        QtCore.QObject.connect(MainWindow, QtCore.SIGNAL("close()"), self.shutDown)

        # Create instance of updateTableClass to update of tables
        self.updateTableInstance = updateTableClass()
        self.updateTableInstance.updateTableConnection.connect(self.updateTableConnectionFunction)
        self.updateTableInstance.updateTableMessage.connect(self.updateTableMessageFunction)
        self.updateTableInstance.updateTablePacket.connect(self.updateTablePacketFunction)
        # analyst's error
        self.errorAnalystInstance = errorAnalyst()
        self.errorAnalystInstance.error.connect(self.messageError)
        # create Analyst Program
        self.analystProgram = Analyst(self.pathDataBase, self.nameDataBase, self.pathDataOfPacket, self.updateTableInstance, self.deviceSelected[0], self.errorAnalystInstance, self.charToRoute)
        self.analystProgram.setDaemon(True)
        # create cleaner
        self.cleanerInstance = Cleaner(self.updateTableInstance, self.pathDataBase + self.nameDataBase, self.pathDataOfPacket, self.charToRoute)
        self.cleanerInstance.setDaemon(True)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(_translate("Proyecto", "Sniffer Project", None))
        self.menuFile.setTitle(_translate("Proyecto", "File", None))
        self.actionStart.setText(_translate("Proyecto", "Start Sniffing", None))
        self.actionStart.setShortcut(_translate("Proyecto", "Ctrl+S", None))
        self.actionSelectDevice.setText(_translate("Proyecto", "Select device", None))
        self.actionSelectDevice.setShortcut(_translate("Proyecto", "Ctrl+A", None))
        self.actionInsertTableRoute.setText(_translate("Proyecto", "Insert routing table", None))
        self.actionInsertTableRoute.setShortcut(_translate("Proyecto", "Ctrl+R", None))
        self.actionConfigDataBase.setText(_translate("Proyecto", "Edit config file", None))
        self.actionConfigDataBase.setShortcut(_translate("Proyecto", "Ctrl+E", None))
        self.actionSystemUpdateTable.setText(_translate("Proyecto", "Activate system updateTable", None))
        self.actionSystemUpdateTable.setShortcut(_translate("Proyecto", "Ctrl+U", None))
        self.actionClearDB.setText(_translate("Proyecto", "Clear Data Base", None))
        self.actionClearDB.setShortcut(_translate("Proyecto", "Ctrl+D", None))
        self.actionExit.setText(_translate("Proyecto", "Exit", None))
        self.actionExit.setShortcut(_translate("Proyecto", "Ctrl+F4", None))
        # menu to graphics
        self.menuGraphics.setTitle(_translate("Proyecto", "Graphics", None))
        self.actionFirtsGraphics.setText(_translate("Proyecto", "Graphic for date", None))
        self.actionFirtsGraphics.setShortcut(_translate("Proyecto", "Ctrl+1", None))
        self.actionSecondGraphics.setText(_translate("Proyecto", "Graphic for type traffic", None))
        self.actionSecondGraphics.setShortcut(_translate("Proyecto", "Ctrl+2", None))
        self.actionThirdGraphics.setText(_translate("Proyecto", "Graphic for type attack", None))
        self.actionThirdGraphics.setShortcut(_translate("Proyecto", "Ctrl+3", None))
        self.actionFourthGraphics.setText(_translate("Proyecto", "Graphic for country", None))
        self.actionFourthGraphics.setShortcut(_translate("Proyecto", "Ctrl+4", None))
        self.actionFiveGraphics.setText(_translate("Proyecto", "Graphic number packet for date", None))
        self.actionFiveGraphics.setShortcut(_translate("Proyecto", "Ctrl+5", None))
        self.actionSixGraphics.setText(_translate("Proyecto", "Graphic number packet for type traffic", None))
        self.actionSixGraphics.setShortcut(_translate("Proyecto", "Ctrl+6", None))
        # action help
        self.actionHelp.setText(_translate("Proyecto", "Help", None))
        self.actionHelp.setShortcut(_translate("Proyecto", "Ctrl+H", None))

    # Functions of actions MainWindows

    def actionStart_clicked(self):
        if self.cleanerInstance.executed == False:
            if self.actionStart.text() == "Start Sniffing":
                if self.deviceSelected[0] == "":
                    deviceList = pcapy.findalldevs()
                    self.dialog = QtGui.QDialog()
                    self.dialog.ui = jDialogSelectDevice()
                    self.dialog.ui.setupUi(self.dialog, deviceList)
                    self.dialog.ui.signalDeviceSelected.connect(self.changeDevice)
                    self.dialog.exec_()

                if self.analystProgram.device != "":
                    try:
                        query = QtSql.QSqlQuery('SELECT id FROM routingTable', self.db)
                        query.next()
                        if query.isNull(0):
                            error = "RoutingTable don't have any row. Please stop sniffing if you want to detect TTL attack, you would insert the routing table"
                            self.messageError(error)
                        self.analystProgram.start()
                        self.actionStart.setText(_translate("Proyecto", "Stop Sniffing", None))
                    except BaseException as e:
                         print('Error al lanzar de nuevo el analizador'.format(e))
                else:
                    error = "If you want to start analyst, you would select the device that you want to sniffing"
                    self.messageError(error)
            else:
                # self.analystProgram.is_alive = False
                # self.analystProgram.stopSniffer()
                self.actionStart.setText(_translate("Proyecto", "Start Sniffing", None))
                self.analystProgram.stopSniffer()
                i = 0
                while self.analystProgram.isAlive():
                    i += 1
                    time.sleep(0.01)
                self.analystProgram = Analyst(self.pathDataBase, self.nameDataBase, self.pathDataOfPacket, self.updateTableInstance, self.deviceSelected[0], self.errorAnalystInstance, self.charToRoute)
                self.analystProgram.setDaemon(True)

    def actionSelectDevice_clicked(self):
        deviceList = pcapy.findalldevs()
        self.dialog = QtGui.QDialog()
    	self.dialog.ui = jDialogSelectDevice()
        self.dialog.ui.setupUi(self.dialog, deviceList)
        self.dialog.ui.signalDeviceSelected.connect(self.changeDevice)
        self.dialog.show()

    def actionInsertTableRoute_clicked(self):
        self.dialog = QtGui.QDialog()
    	self.dialog.ui = jDialogTableRoute()
        self.dialog.ui.setupUi(self.dialog, self.pathDataBase + self.nameDataBase)
        self.dialog.show()

    def actionSelectRow_doubleClicked_connection(self):
        index = self.listConnections.currentIndex().row() + 1
        self.modelDetailMessage.setFilter('"id connection"'+" LIKE '"+str(index)+"'")

    def actionSelectRow_doubleClicked_message(self):
        idFile = self.listMessage.selectedIndexes()[7]
        idFile = self.listMessage.model().data(idFile).toString()
        query = QtSql.QSqlQuery('SELECT rowid FROM message WHERE "id file or directory" LIKE '+idFile, self.db)
        query.next()
        id = query.value(0).toString()
        fragmentation = self.listMessage.selectedIndexes()[2]
        fragmentation = self.listMessage.model().data(fragmentation).toString()
        pathofFile = self.listMessage.selectedIndexes()[6]
        pathofFile = self.listMessage.model().data(pathofFile).toString()
        if fragmentation == "1":
            self.modelListPacket.setFilter('"id message"'+" LIKE'"+str(id)+"'")
            if os.path.isfile(pathofFile):
                self.dialogData = QtGui.QDialog()
                self.dialogData.ui = jDialogData()
                self.dialogData.ui.setupUi(self.dialogData, pathofFile)
                self.dialogData.show()
        else:
            if os.path.isfile(pathofFile):
                self.dialogData = QtGui.QDialog()
                self.dialogData.ui = jDialogData()
                self.dialogData.ui.setupUi(self.dialogData, pathofFile)
                self.dialogData.show()
            else:
                self.dialogError = QtGui.QDialog()
                self.dialogError.ui = jDialogError()
                self.dialogError.ui.setupUi(self.dialogError, "This message don't have data")
                self.dialogError.show()

    def actionSelectRow_doubleClicked_packet(self):
        pathofFile = self.listPacket.selectedIndexes()[6]
        pathofFile = self.listPacket.model().data(pathofFile).toString()
        if os.path.isfile(pathofFile):
            self.dialogData = QtGui.QDialog()
            self.dialogData.ui = jDialogData()
            self.dialogData.ui.setupUi(self.dialogData, pathofFile)
            self.dialogData.show()
        else:
            self.dialogError = QtGui.QDialog()
            self.dialogError.ui = jDialogError()
            self.dialogError.ui.setupUi(self.dialogError, "This packet don't have data")
            self.dialogError.show()

    def actionConfigDataBase_clicked(self):
        if self.analystProgram.isAlive():
            error = "Please stop analyst, if you want to change the configuration"
            self.messageError(error)
        else:
            self.dialogConfig = QtGui.QDialog()
            self.dialogConfig.ui = jDialogConfig()
            self.dialogConfig.ui.setupUi(self.dialogConfig, self.pathDataBase, "not initial")
            self.dialogConfig.ui.changeConfig.connect(self.changeConfiguration)
            self.dialogConfig.show()

    def actionHelp_clicked(self):
        self.dialogHelp = QtGui.QDialog()
    	self.dialogHelp.ui = jDialogHelp()
        self.dialogHelp.ui.setupUi(self.dialogHelp)
        self.dialogHelp.show()

    def actionClearDB_clicked(self):
        if self.actionStart.text() == "Stop Sniffing":
            self.dialogError = QtGui.QDialog()
            self.dialogError.ui = jDialogError()
            self.dialogError.ui.setupUi(self.dialogError, "Please, you have to stop sniffing before that start the clean process.")
            self.dialogError.show()
        else:
            if self.cleanerInstance.isAlive() != True:
                yesterday = date.today() - timedelta(days=1)
                dateSelect = str(yesterday) + " " + strftime("%H:%M:%S", gmtime())
                if self.cleanerInstance.executed == False:
                    self.dialogInsertDate = QtGui.QDialog()
                    self.dialogInsertDate.ui = jDialogInsertDate()
                    self.dialogInsertDate.ui.setupUi(self.dialogInsertDate, dateSelect)
                    self.dialogInsertDate.ui.signalDateToCleaner.connect(self.cleanerInstance.changeDate)
                    self.dialogInsertDate.exec_()
                    if self.cleanerInstance.dateSelect != "":
                        self.cleanerInstance.start()
                    else:
                        error = "Please you should insert the date, if you want to execute Cleaner process"
                        self.messageError(error)
                else:
                    self.cleanerInstance = Cleaner(self.updateTableInstance, self.pathDataBase + self.nameDataBase, self.pathDataOfPacket, self.charToRoute)
                    self.cleanerInstance.setDaemon(True)
                    self.dialogInsertDate = QtGui.QDialog()
                    self.dialogInsertDate.ui = jDialogInsertDate()
                    self.dialogInsertDate.ui.setupUi(self.dialogInsertDate, dateSelect)
                    self.dialogInsertDate.ui.signalDateToCleaner.connect(self.cleanerInstance.changeDate)
                    self.dialogInsertDate.exec_()
                    if self.cleanerInstance.dateSelect != "":
                        self.cleanerInstance.start()
            else:
                error = "Cleaner process is executing, Please you wait for it finish"
                self.messageError(error)

    def actionActivateSystemUpdateTable_clicked(self):
        self.dialogUpdateTable = QtGui.QDialog()
        self.dialogUpdateTable.ui = jDialogActivateUpdateTable()
        self.dialogUpdateTable.ui.setupUi(self.dialogUpdateTable)
        self.dialogUpdateTable.ui.activateUpdateTableSytem.connect(self.changeUpdateTable)
        self.dialogUpdateTable.show()

    # Graphics

    def actionFirtsGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT * FROM information')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        value = list()
        axisX = list(list())
        for i in range(len(data)):
            value.append((float(data[i][1])/float(data[i][0]))* 100)
            date = str(data[i][2])
            date.replace('u', '')
            date1 = str(data[i][3])
            date1.replace('u', '')
            axisX.append((date, date1))
        plt.bar(np.arange(len(axisX)), value)
        plt.ylim(0.0, 100.0)
        plt.title("Percentage of dangerous packet")
        plt.xticks(np.arange(len(axisX)), axisX, rotation = 10)
        plt.show()

    def actionSecondGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT * FROM information')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        value = [0, 0 ,0]
        axisX = ['TCP', 'ICMP', 'UDP']
        for i in range(len(data)):
            value[0] += data[i][4]
            value[1] += data[i][5]
            value[2] += data[i][6]
        plt.bar(np.arange(len(axisX)), value, align="center")
        if value[0] >= value[1] and value[0] >= value[2]:
            plt.ylim(0, value[0] + 100)
        elif  value[1] > value[0] and value[1] > value[2]:
            plt.ylim(0, value[1] + 100)
        else:
            plt.ylim(0, value[2] + 100)
        plt.title("Number of dangerous packet for each type of traffic")
        plt.xticks(np.arange(len(axisX)), axisX)
        plt.show()

    def actionThirdGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT "Type Attack" FROM connection')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        value = [0, 0, 0, 0]
        axisX = ["TTL attack", "RST attack", "SYN attack", "Fragmentation attack"]
        for i in range(len(data)):
            if ((data[i][0] | 0xE) ^ 0xE):
                value[0] += 1
            if ((data[i][0] | 0xD) ^ 0xD):
                value[1] += 1
            if ((data[i][0] | 0xB) ^ 0xB):
                value[2] += 1
            if ((data[i][0] | 0x7) ^ 0x7):
                value[3] += 1
        plt.bar(np.arange(len(axisX)), value, align="center")
        if len(data) >= 10:
            plt.ylim(0, len(data) + ((len(data) * 10)/100))
        else:
            plt.ylim(0, len(data) + 6)
        plt.title("Number of dangerous packet for each type of attack")
        plt.xticks(np.arange(len(axisX)), axisX)
        plt.show()

    def actionFourthGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT Country FROM connection')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        value = list()
        value.append(0)
        axisX = list()
        axisX.append("unknown")
        countryInArray = False
        for i in range(len(data)):
            if data[i][0] != "":
                countryInArray = False
                for j in range(len(axisX)):
                    if data[i][0] == axisX[j]:
                        value[j] += 1
                        countryInArray = True
                        break
                if countryInArray == False:
                    axisX.append(data[i][0])
                    value.append(1)
            else:
                value[0] += 1
        plt.bar(np.arange(len(axisX)), value, align="center")
        if len(data) >= 10:
            plt.ylim(0, len(data) + ((len(data) * 10)/100))
        else:
            plt.ylim(0, len(data) + 6)
        plt.title("Number of dangerous packet for each country")
        plt.xticks(np.arange(len(axisX)), axisX)
        plt.show()

    def actionFiveGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT * FROM information')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        axisY = 0
        value = list()
        axisX = list(list())
        for i in range(len(data)):
            value.append(float(data[i][0]))
            if data[i][0] > axisY:
                axisY = data[i][0]
            date = str(data[i][2])
            date.replace('u', '')
            date1 = str(data[i][3])
            date1.replace('u', '')
            axisX.append((date, date1))
        plt.bar(np.arange(len(axisX)), value)
        plt.ylim(0.0, axisY + 500)
        plt.title("Number of packet receive")
        plt.xticks(np.arange(len(axisX)), axisX, rotation = 10)
        plt.show()

    def actionSixGraphics_clicked(self):
        connectionDataBase = sqlite3.connect(self.pathDataBase + self.nameDataBase, 10000)
        cursorDataBase = connectionDataBase.cursor()
        cursorDataBase.execute('SELECT * FROM information')
        data = cursorDataBase.fetchall()
        connectionDataBase.close()
        value = [0, 0 ,0]
        axisX = ['TCP', 'ICMP', 'UDP']
        for i in range(len(data)):
            value[0] += data[i][7]
            value[1] += data[i][8]
            value[2] += data[i][9]
        plt.bar(np.arange(len(axisX)), value, align="center")
        if value[0] >= value[1] and value[0] >= value[2]:
            plt.ylim(0, value[0] + 100)
        elif  value[1] > value[0] and value[1] > value[2]:
            plt.ylim(0, value[1] + 100)
        else:
            plt.ylim(0, value[2] + 100)
        plt.title("Number of packet for each type of traffic")
        plt.xticks(np.arange(len(axisX)), axisX)
        plt.show()

    # Functions's Jdialog

    def updateTableConnectionFunction(self):
        if self.activateSystemUpdateTable == True:
            if self.limitUpdateTable <= self.numberUpdateTable:
                self.modelListConnections.select()
                self.listConnections.resizeColumnsToContents()
        else:
            self.modelListConnections.select()
            self.listConnections.resizeColumnsToContents()
        QtGui.qApp.processEvents()

    def updateTableMessageFunction(self):
        if self.activateSystemUpdateTable == True:
            if self.limitUpdateTable <= self.numberUpdateTable:
                self.modelDetailMessage.select()
                self.listMessage.resizeColumnsToContents()
        else:
            self.modelDetailMessage.select()
            self.listMessage.resizeColumnsToContents()
        QtGui.qApp.processEvents()

    def updateTablePacketFunction(self):
        if self.activateSystemUpdateTable == True:
            if self.limitUpdateTable <= self.numberUpdateTable:
                self.modelListPacket.select()
                self.listPacket.resizeColumnsToContents()
                if self.lastDateUpdateTable == 0:
                    # self.lastDateUpdateTable = time.mktime(datetime.strptime(gmtime(), "%Y-%m-%d %H:%M:%S").timetuple())
                    # print str(time.mktime(datetime.datetime.now()))
                    self.lastDateUpdateTable = time.time()
                    self.limitUpdateTable = 10
                else:
                    auxiliarTime = time.time()
                    if (self.lastDateUpdateTable + 10) > auxiliarTime:
                        self.limitUpdateTable += int((self.lastDateUpdateTable + 10) - auxiliarTime)
                    else:
                        self.limitUpdateTable -= int(auxiliarTime - (self.lastDateUpdateTable + 10))
                self.numberUpdateTable = 0
            else:
                self.numberUpdateTable += 1
            if self.limitUpdateTable > 20 or self.limitUpdateTable < 5:
                self.limitUpdateTable = 10
        else:
            self.modelListPacket.select()
            self.listPacket.resizeColumnsToContents()
        QtGui.qApp.processEvents()

    def changeDevice(self, value):
        self.deviceSelected = list()
        for i in range(len(value)):
            self.deviceSelected.append(str(value[i]))
        # QtGui.qApp.processEvents()
        if self.analystProgram.isAlive():
            self.actionStart.emit(QtCore.SIGNAL(_fromUtf8("activated()")))
        else:
            self.analystProgram.changeDevice(self.deviceSelected[0])

    def messageError(self, error):
        self.dialogError = QtGui.QDialog()
        self.dialogError.ui = jDialogError()
        self.dialogError.ui.setupUi(self.dialogError, error, "Error")
        self.dialogError.show()

    def messageCaution(self, caution):
        self.dialogError = QtGui.QDialog()
        self.dialogError.ui = jDialogError()
        self.dialogError.ui.setupUi(self.dialogError, caution, "Caution")
        self.dialogError.show()

    def changeConfiguration(self, changeField):
        changeDataBase = False

        if changeField[1] != self.pathDataBase:
            self.pathDataBase = changeField[1]
            changeDataBase = True
            if not os.path.isdir(self.pathDataBase):
                os.makedirs(self.pathDataBase)

        if changeField[2] != self.pathDataOfPacket:
            self.pathDataOfPacket = changeField[2]
            self.analystProgram.pathDataOfPacket = changeField[2]
            if not os.path.isdir(self.pathDataOfPacket):
                os.makedirs(self.pathDataOfPacket)

        if changeField[0] != self.nameDataBase:
            self.nameDataBase = changeField[0]
            changeDataBase = True
            if not os.path.isfile(self.pathDataBase + self.nameDataBase):
                defineDataBase(self.pathDataBase, self.nameDataBase)

        fileConfig = open('config.txt', 'r')
        for i in range(3):
            fileConfig.readline()
        contentFile = fileConfig.read()
        fileConfig.close()

        fileConfig = open('config.txt', 'w')
        fileConfig.write("nameDataBase = '" + self.nameDataBase + "'\n")
        fileConfig.write("pathDataBase = '" + self.pathDataBase + "'\n")
        fileConfig.write("pathDataOfPacket = '" + self.pathDataOfPacket + "'\n")
        fileConfig.write(contentFile)
        fileConfig.close()
        if changeDataBase == True:
            caution = "When you change data base, you should reboot program for GUI is connected with new data base"
            self.messageCaution(caution)

    def changeUpdateTable(self, value):
        self.activateSystemUpdateTable = value

    # functions's PopMenu of ListConnections

    def contextMenuListConnection(self, point):
        # show context menu
        self.popMenuListConnection.exec_(self.listConnections.mapToGlobal(point))

    def actionStopRefreshPopMenuListConnection_clicked(self):
        if self.actionStopRefreshPopMenuListConnections.text() == "Stop Refresh":
            self.actionStopRefreshPopMenuListConnections.setText("Start Refresh")
            self.updateTableInstance.updateTableConnectionActivate = False
        else:
            self.actionStopRefreshPopMenuListConnections.setText("Stop Refresh")
            self.updateTableInstance.updateTableConnectionActivate = True

    # function's PopMenu of ListMessage

    def contextMenuListMessage(self, point):
        # show context menu
        self.popMenuListMessage.exec_(self.listMessage.mapToGlobal(point))

    def actionStopRefreshPopMenuListMessage_clicked(self):
        if self.actionStopRefreshPopMenuListMessage.text() == "Stop Refresh":
            self.actionStopRefreshPopMenuListMessage.setText("Start Refresh")
            self.updateTableInstance.updateTableMessageActivate = False
        else:
            self.actionStopRefreshPopMenuListMessage.setText("Stop Refresh")
            self.updateTableInstance.updateTableMessageActivate = True

    def actionClearFilterPopMenuListMessage_clicked(self):
        self.modelDetailMessage.setFilter("")

    # function's PopMenu of ListPacket

    def contextMenuListPacket(self, point):
        # show context menu
        self.popMenuListPacket.exec_(self.listPacket.mapToGlobal(point))

    def actionStopRefreshPopMenuListPacket_clicked(self):
        if self.actionStopRefreshPopMenuListPacket.text() == "Stop Refresh":
            self.actionStopRefreshPopMenuListPacket.setText("Start Refresh")
            self.updateTableInstance.updateTablePacketActivate = False
        else:
            self.actionStopRefreshPopMenuListPacket.setText("Stop Refresh")
            self.updateTableInstance.updateTablePacketActivate = True

    def actionClearFilterPopMenuListPacket_clicked(self):
        self.modelListPacket.setFilter("")

    def shutDown(self):
        if self.actionStart.text() == "Stop Sniffing":
            self.analystProgram.is_alive = False
            while self.analystProgram.isAlive():
                i = 0
        if self.cleanerInstance.executed == False:
            sys.exit(0)
        else:
            self.messageError("Cleaner process is alive, If you wanted to close, you would wait to finish cleaner process")

#Base de datos
def defineDataBase(pathDataBase, nameDataBase):
    connectionDataBase = sqlite3.connect(pathDataBase+nameDataBase, 10000)
    cursorDataBase = connectionDataBase.cursor()

    cursorDataBase.execute('''CREATE TABLE information
            ("Number packet receive" INTEGER,
            "Number dangerous packet" INTEGER,
            "Start time" TEXT,
            "Finish time" TEXT,
            "Number TCP dangerous packet" INTEGER,
            "Number ICMP dangerous packet" INTEGER,
            "Number UDP dangerous packet" INTEGER,
            "Number TCP packet" INTEGER,
            "Number ICMP packet" INTEGER,
            "Number UDP packet" INTEGER)''')

    cursorDataBase.execute('''CREATE TABLE connection
            ("IP Source" TEXT NOT NULL,
            "Port Source" TEXT NOT NULL,
            "Source MAC" TEXT,
            "IP Destination" TEXT NOT NULL,
            "Port Destination" TEXT NOT NULL,
            "Destination MAC" TEXT,
            "Type Traffic" TEXT NOT NULL,
            "Type Attack" INTEGER,
            "Country" TEXT,
            "Time zone" TEXT,
            "Date" TEXT,
            "Description" TEXT,
            "id Directory" INTEGER)''')

    cursorDataBase.execute('''CREATE TABLE message
            ("id connection" INTEGER NOT NULL,
            "id fragmentation" REAL,
            Fragment INTEGER NOT NULL,
            "Politic Fragmentation" TEXT,
            "Date" TEXT,
            Size INTEGER,
            "Path file of string" TEXT,
            "id file or directory" INTEGER,
            FOREIGN KEY("id connection") REFERENCES connection(rowid)) ''')

    cursorDataBase.execute('''CREATE TABLE packet
            ("id connection" INTEGER NOT NULL,
            "id message" INTEGER NOT NULL,
            "Position into message" TXT NOT NULL,
            TTL INTEGER NOT NULL,
            "Date" TEXT,
            Size INTEGER,
            "Path file of data" TEXT,
            "id File" INTEGER,
            FOREIGN KEY("id message") REFERENCES message(rowid),
            FOREIGN KEY("id connection") REFERENCES connection(rowid))''')

    cursorDataBase.execute('''CREATE TABLE routingTable
            (id INTEGER PRIMARY KEY NOT NULL,
            "Destination Address" TEXT NOT NULL,
            "Mask" TEXT NOT NULL,
            "Gateway" TEXT NOT NULL,
            "Interface" TEXT NOT NULL,
            "Metric" TEXT NOT NULL,
            "Politic Fragmentation" TEXT)''')

    # cursorDataBase.execute("INSERT INTO information VALUES (1000,300,'2016-10-5 19:58:00','2016-10-5 20:58:00',150,100,50, 200, 0, 0)")
    # cursorDataBase.execute("INSERT INTO information VALUES (1000,700,'2016-10-5 20:58:00','2016-10-5 22:58:00',500,200,0, 0, 200, 0)")
    # cursorDataBase.execute("INSERT INTO information VALUES (1000,400,'2016-10-5 22:58:00','2016-10-6 19:00:00',200,125,75, 0, 0, 200)")
    # cursorDataBase.execute("INSERT INTO connection VALUES ('192.168.100.101','8080','FF:FF:FF:FF:FF:01','192.168.100.150','8080','94:39:e5:0d:0a:01','TCP',7,'SP','Spain/Jaen','2016-10-01 12:18:50','',1)")
    # cursorDataBase.execute("INSERT INTO connection VALUES ('192.168.100.101','8080','FF:FF:FF:FF:FF:01','192.168.100.124','8080','94:39:e5:0d:0a:01','TCP',7,'SP','Spain/Jaen','2016-10-08 12:18:50','',2)")
    # cursorDataBase.execute("INSERT INTO connection VALUES ('192.168.100.101','8080','FF:FF:FF:FF:FF:01','192.168.100.154','8080','94:39:e5:0d:0a:01','TCP',7,'SP','Spain/Madrid','2016-10-07 12:18:50','',3)")
    # cursorDataBase.execute("INSERT INTO connection VALUES ('192.168.100.101','8080','FF:FF:FF:FF:FF:01','192.168.100.198','8080','94:39:e5:0d:0a:01','TCP',7,'SP','Spain/Granada','2016-10-08 12:18:50','',4)")
    # cursorDataBase.execute("INSERT INTO message VALUES (1, 0, 0, 'DSDB', '2016-07-21 12:18:50', 6555, '',1)")
    # cursorDataBase.execute("INSERT INTO message VALUES (1, 0, 0, 'Microsoft', '2016-07-21 12:18:50', 6555, '',2)")
    # cursorDataBase.execute("INSERT INTO message VALUES (2, 0, 0, 'Linux', '2016-07-21 12:18:50', 6555, '',3)")
    # cursorDataBase.execute("INSERT INTO message VALUES (2, 0, 0, 'DSDB', '2016-07-21 12:18:50', 6555, '/home/gregorio/PycharmProjects/untitled/pathDataOfPacket/idDirectory-2/idDirectoryMessage-4/idFileMessage-4.txt',4)")
    # cursorDataBase.execute("INSERT INTO message VALUES (4, 47488, 1, 'DSDB', '2016-07-21 12:18:50', -1, '',5)")
    # cursorDataBase.execute("INSERT INTO packet VALUES (4, 5, 0, 2, '2016-07-21 12:18:52', 120, '/home/gregorio/PycharmProjects/untitled/pathDataOfPacket/idDirectory-4/idDirectoryMessage-5/idPacket1.txt',1)")
    # cursorDataBase.execute("INSERT INTO packet VALUES (4, 5, 128, 2, '2016-07-21 12:18:53', 112, '/home/gregorio/PycharmProjects/untitled/pathDataOfPacket/idDirectory-4/idDirectoryMessage-5/idPacket2.txt',2)")
    # cursorDataBase.execute("INSERT INTO packet VALUES (4, 5, 256, 2, '2016-07-21 12:18:54', 88, '/home/gregorio/PycharmProjects/untitled/pathDataOfPacket/idDirectory-4/idDirectoryMessage-5/idPacket3.txt',3)")
    cursorDataBase.execute("INSERT INTO routingTable VALUES (1, '8.8.8.8', '255.255.255.255', '192.168.1.1', 'eth0', '4', 'DSDB')")
    cursorDataBase.execute("INSERT INTO routingTable VALUES (2, '90.192.168.100', '255.255.255.255', '192.168.1.1', 'eth0', '3', 'DSDB')")
    connectionDataBase.commit()
    connectionDataBase.close()

def createConnection(pathDataBase, nameDataBase):
    db = QtSql.QSqlDatabase.addDatabase("QSQLITE")
    db.setDatabaseName(pathDataBase + nameDataBase)
    db.open()
    print(db.lastError().text())
    return db

if __name__ == "__main__":
    charToRoute = ""
    system = sys.platform
    if system.find("linux") != -1 or system.find("ubuntu") != -1:
        charToRoute = "/"
    elif system.find("win") != -1:
        charToRoute = "\\"
    else:
        charToRoute = "/"
    nameDataBase = ""
    pathDataBase = ""
    app = QtGui.QApplication(sys.argv)
    if not os.path.isfile("config.txt"):
        # create of file config and specify name of data base and address
        fileConfig = open('config.txt', 'w')
        fileConfig.write("nameDataBase = 'dataBaseDefault'\n")
        pathDataBase = os.path.abspath('config.txt')
        pathDataBase = pathDataBase.replace("config.txt","")
        fileConfig.write("pathDataBase = '" + pathDataBase + "'\n")
        pathDataOfPacket = pathDataBase + "pathDataOfPacket"
        fileConfig.write("pathDataOfPacket = '" + pathDataOfPacket + "'\n")
        fileConfig.write("\n\nCAUTION!! Don't delete and don't move without the program file. This file is a config file")
        fileConfig.write("\nInstructions: \nPlease, respect format of this file. In this file you can specify path of dataBase the same as dataBase's name")
        fileConfig.close()

        dialogConfig = QtGui.QDialog()
    	dialogConfig.ui = jDialogConfig()
        dialogConfig.ui.setupUi(dialogConfig, pathDataBase, "initial")
        dialogConfig.exec_()
        # read file after that user modify
        file = open(pathDataBase+'config.txt','r')
        nameDataBase = file.readline()
        pathDataBase = file.readline()
        pathDataOfPacket = file.readline()
        file.close()

        # Clean name of database
        nameDataBase = nameDataBase.replace("nameDataBase = '", "")
        nameDataBase = nameDataBase.replace("'","")
        nameDataBase = nameDataBase.replace("\n", "")
        pathDataBase = pathDataBase.replace("pathDataBase = '", "")
        pathDataBase = pathDataBase.replace("'", "")
        pathDataBase = pathDataBase.replace("\n", "")
        pathDataOfPacket = pathDataOfPacket.replace("pathDataOfPacket = '", "")
        pathDataOfPacket = pathDataOfPacket.replace("'", "")
        pathDataOfPacket = pathDataOfPacket.replace("\n", "")

        if not os.path.isdir(pathDataOfPacket):
            os.makedirs(pathDataOfPacket)
        if not os.path.isfile(pathDataBase + nameDataBase):
            defineDataBase(pathDataBase, nameDataBase)
    else:
        file = open('config.txt','r')
        nameDataBase = file.readline()
        pathDataBase = file.readline()
        pathDataOfPacket = file.readline()
        file.close()

        # Clean name of database
        nameDataBase = nameDataBase.replace("nameDataBase = '","")
        nameDataBase = nameDataBase.replace("'","")
        nameDataBase = nameDataBase.replace("\n","")
        pathDataBase = pathDataBase.replace("pathDataBase = '","")
        pathDataBase = pathDataBase.replace("'","")
        pathDataBase = pathDataBase.replace("\n","")
        pathDataOfPacket = pathDataOfPacket.replace("pathDataOfPacket = '", "")
        pathDataOfPacket = pathDataOfPacket.replace("'", "")
        pathDataOfPacket = pathDataOfPacket.replace("\n", "")

        if not os.path.isfile(pathDataBase + nameDataBase):
            defineDataBase(pathDataBase, nameDataBase)
        if not os.path.isdir(pathDataOfPacket):
            os.makedirs(pathDataOfPacket)

    db = createConnection(pathDataBase, nameDataBase)
    MainWindow = QtGui.QMainWindow()
    ui = Proyecto_MainWindows()
    ui.setupUi(MainWindow, nameDataBase, pathDataBase, pathDataOfPacket, db, charToRoute)
    MainWindow.show()
    sys.exit(app.exec_())

'''
    ethmsg.py
    Implementación del protocolo de mensajeria basica para emision de mensajes en tiempo real sobre ethernet.
    Autor: Manuel Ruiz <manuel.ruiz.fernandez@uam.es>
    2024 EPS-UAM
'''

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

ETHTYPE = 0x3003
#Dirección de difusión (Broadcast)
broadcast = bytes([0xFF]*6)




def process_ethMsg_frame(us:ctypes.c_void_p,header:pcap_pkthdr,data:bytes,srcMac:bytes) -> None:
    '''
        Nombre: process_EthMsg_frame
        Descripción: Esta función procesa las tramas mensajes sobre ethernet. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype ETHTYPE (si ha sido registrada en initEth). 
                - Imprimir el contenido de los datos indicando la direccion MAC del remitente, la dirección IP de destino (en notación decimal a.b.c.d), asi como el tiempo de recepcion del mensaje, según el siguiente formato:
					[<segundos.microsegundos>] <MAC> -> <IP>: <mensaje> 
                - En caso de que no exista retornar
            
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ethMsg
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    string = ""
    ethSrc = bytearray()
    ipDest = bytearray()
    msj = bytearray()

    if header == None:
        return
    
    ipDest = data[0:4]
    ipDestFormatted = '.'.join(str(b) for b in ipDest)
    mac_formatted = ':'.join(['{:02X}'.format(b) for b in srcMac])
    msj = data[4:]
    formatted_time = f'{header.ts.tv_sec}.{header.ts.tv_usec}'
    string = "[" + formatted_time + "] " + mac_formatted + " -> " + ipDestFormatted + ": " + msj.decode().split('\x00')[0]
    print(string) 

def initEthMsg(interface:str) -> int:
    '''
        Nombre: initEthMsg
        Descripción: Esta función construirá inicializará el nivel ethMsg. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_ethMsg_frame con el Ethertype ETHTYPE
        Argumentos:   
			interfaz
    '''

    registerEthCallback(process_ethMsg_frame, 0x3003)

    return 0
 
def sendEthMsg(ip:int, message:bytes) -> int:
    '''
        Nombre: sendEthMsg
        Descripción: Esta función mandara un mensaje en broacast 
            
            Esta función debe realizar, al menos, las siguientes tareas:
                - Crear una trama Ehernet con el mensaje remitido
                - Enviar un mensaje en broadcast
		Argumentos:
			ip: Direccion IP a la que remitir el mensaje. Enviar como una palabra de 32 bits en orden de red.
			message: datos con el mensaje a remitir.
                
        Retorno: 
			Numero de Bytes transmitidos en el mensaje.
			None en caso de que no haya podido emitir el mensaje
                
          
    '''

    packet = bytearray()
    packet+=struct.pack('!I', ip)
    packet+=bytes(message.encode())
    

    if sendEthernetFrame(packet, len(packet), 0x3003, broadcast) == -1:
        return None
    
    return len(packet)

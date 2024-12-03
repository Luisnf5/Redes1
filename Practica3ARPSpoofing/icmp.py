'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
import datetime
from ip import *
from threading import Lock
import struct
import logging  # Added import for logging

ICMP_PROTO = 1


ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

timeLock = Lock()
icmp_send_times = {}

def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    # Si la longitud del mensaje es impar, añade un byte a 0
    if len(msg) % 2 != 0:
        msg += b'\0'
    
    s = 0
    for i in range(0, len(msg), 2):
        a = msg[i]
        b = msg[i + 1]
        s = s + (a + (b << 8))
    
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    global timeLock, icmp_send_times

    icmp_header1 = struct.unpack('!BB', data[:2])
    icmp_type = icmp_header1[0]
    icmp_code = icmp_header1[1]
    icmp_checksum = struct.unpack('H', data[2:4])[0]
    icmp_header2 = struct.unpack('!HH', data[4:8])
    icmp_id = icmp_header2[0]
    icmp_seqnum = icmp_header2[1]
    
    data_sin_chksum = data[:2] + b'\x00\x00' + data[4:]

    if chksum(data_sin_chksum) != icmp_checksum:
        logging.debug("Checksum incorrecto")
        return
    
    logging.debug(f"Tipo: {icmp_type}, Código: {icmp_code}")

    if icmp_type == ICMP_ECHO_REQUEST_TYPE:
        sendICMPMessage(data[8:], ICMP_ECHO_REPLY_TYPE, icmp_code, icmp_id, icmp_seqnum, srcIp)
    elif icmp_type == ICMP_ECHO_REPLY_TYPE:
        key = f"{srcIp}-{icmp_id}-{icmp_seqnum}"
        send_time = None
        with timeLock:
            send_time = icmp_send_times.get(key)  # Use get to avoid KeyError
        
        if send_time is None:
            logging.debug("No se ha encontrado el tiempo de envío")
            return
        
        recv_time = header.ts.tv_sec + (header.ts.tv_usec / 1000000)
        rtt = round(recv_time - send_time, 3)
        logging.debug(f"RTT: {rtt} s")
    else:
        return

    

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''
    global icmp_send_times, timeLock

    if type not in [ICMP_ECHO_REQUEST_TYPE, ICMP_ECHO_REPLY_TYPE]:
        return False

    # Construir la cabecera ICMP
    icmp_header = struct.pack('!BBHHH', type, code, 0, icmp_id, icmp_seqnum)
    icmp_message = icmp_header + data

    if len(icmp_message) % 2 != 0:
        icmp_message += b'\0'

    # Calcular el checksum
    checksum = chksum(icmp_message)
    icmp_header1 = struct.pack('!BB', type, code)
    checksum = struct.pack('H', checksum)
    icmp_header2 = struct.pack('!HH', icmp_id, icmp_seqnum)
    icmp_header = icmp_header1 + checksum + icmp_header2

    icmp_message = icmp_header + data

    if type == ICMP_ECHO_REQUEST_TYPE:
        # Guardar el tiempo de envío
        key = f"{dstIP}-{icmp_id}-{icmp_seqnum}"
        with timeLock:
            icmp_send_times[key] = time.time() 

    
    return sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)

def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)
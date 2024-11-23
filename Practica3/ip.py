'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#IPID a numero de pareja
IPID = None

#Declaración de variables globales
myIP = None
MTU = None
netmask = None
defaultGW = None
ipOpts = None




def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0xa29f    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''initARP
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    global MTU
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    ver_ihl = data[0]
    ihl = ver_ihl & 0x0F

    header_len = ihl*4

    ip_header1 = struct.unpack('!BBHHHBB', data[:10])
    ip_header_checksum = struct.unpack('H', data[10:12])
    ip_header2 = struct.unpack('!II', data[12:20])

    ver_ihl = ip_header1[0]
    type_of_service = ip_header1[1]
    total_length = ip_header1[2]
    ipid = ip_header1[3]
    fragm_data = ip_header1[4]
    ttl = ip_header1[5]
    protocol = ip_header1[6]
    checksum = ip_header_checksum[0]
    src_ip = ip_header2[0]
    dst_ip = ip_header2[1]

    if header_len > 20:
        ipOpts = data[20:header_len]
        logging.debug("Opciones IP: %s", ipOpts)

    calculated_checksum = chksum(data[:10] + data[12:header_len])
    if checksum != calculated_checksum:
        logging.debug("Checksum incorrecto %d %d", checksum, calculated_checksum)
        return
    
    flags = fragm_data & 0xE000
    offset = fragm_data & 0x1FFF
    Res = (flags >> 15) & 1
    DF = (flags >> 14) & 1
    MF = (flags >> 13) & 1

    if offset != 0:
        logging.info("Reensamblado no implementado, deshechando datagrama...")
        return
    

    logging.debug('Longitud de la cabecera IP: %d', (ver_ihl & 0x0F)*4)
    logging.debug('IPID: %d', ipid)
    logging.debug('TTL: %d', ttl)
    logging.debug('Valor de las banderas DF y MF: %d %d', DF, MF)
    logging.debug('Valor de offset: %d', offset)
    ipSrcFormatted = '.'.join(str(b) for b in struct.pack('!I', src_ip))
    logging.debug('IP origen: %s', ipSrcFormatted)
    ipDstFormatted = '.'.join(str(b) for b in struct.pack('!I', dst_ip))
    logging.debug('IP destino: %s', ipDstFormatted)
    logging.debug('Protocolo: %d', protocol)

    if protocol in protocols:
        protocols[protocol](us,header,data[20:],src_ip)
    else:
        logging.debug("Protocolo no registrado")

def registerIPProtocol(callback_func: Callable[[ctypes.c_void_p,pcap_pkthdr,bytes,bytes],None], protocol:int):
    global protocols
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    
    protocols[protocol] = callback_func
    

def initIP(interface,opts=None) -> bool:
    global myIP, MTU, netmask, defaultGW, ipOpts, IPID
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''

    if initARP(interface) == -1:
        logging.error("Error inicializando ARP")
        return False
    
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts

    registerEthCallback(process_IP_datagram,0x0800)
    IPID = 5

    return True

def sendIPDatagram(dstIP,data,protocol):
    global IPID, myIP, ipOpts
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    if (ipOpts == None):
        max_data_len = MTU - 20
    else:
        max_data_len = MTU - 20 - len(ipOpts)

    fragments = []
    fragmented = False
    f_offset = 0x0000

    vers = 0x40
    if ipOpts != None:
        ihl = 0x05 + (len(ipOpts) // 4)
    else:
        ihl = 0x05
    
    verIHL = vers | ihl

    #CALCULO DE FRAGMENTO/S
    if len(data) > max_data_len:
        fragmented = True
        if max_data_len % 8 != 0:
            max_data_len = max_data_len - max_data_len % 8
            
        i = 0
        while (len(data) > max_data_len):
            fragments.append(data[:max_data_len])
            data = data[max_data_len:]
            
            i += 1  


        if len(data) != 0:
            fragments.append(data)


        
    else:
        fragments.append(data)

    #ENVIO DE FRAGMENTO/S
    i = 0
    for data in fragments:
        if fragmented:
            if data == fragments[0]:
                f_offset = 0x2000
            else:
                real_offset = (max_data_len*i >> 3)
                if data == fragments[len(fragments)-1]:
                    flags = 0x0000
                else:
                    flags = 0x2000
                
                f_offset = flags | real_offset

        ip_header_chk = struct.pack('!BBHHHBBHII',
                                verIHL,             #   VERSION & IHL (4b + 4b) (1B)
                                0x01,               #   TYPE OF SERVICE (1B)
                                len(data) + ihl*4,  #   TOTAL LENGTH (2B)
                                IPID,               #   IDENTIFICATION (2B)
                                f_offset,           #   FLAGS & OFFSET (3b + 13b) (2B)
                                0x40,               #   TIME TO LIVE (1B)
                                protocol,           #   PROTOCOL (1B)
                                0,                  #   HEADER CHECKSUM (2B)
                                myIP,               #   SOURCE ADDRESS (4B)
                                dstIP)              #   DESTINATION ADDRESS (4B)
        
        if (ipOpts != None):
            checksum = struct.pack('H', chksum(ip_header_chk + ipOpts))
        else:
            checksum = struct.pack('H', chksum(ip_header_chk))

        ip_header1 = struct.pack('!BBHHHBB',
                                verIHL,             #   VERSION & IHL (4b + 4b) (1B)
                                0x01,               #   TYPE OF SERVICE (1B)
                                len(data) + ihl*4,  #   TOTAL LENGTH (2B)
                                IPID,               #   IDENTIFICATION (2B)
                                f_offset,           #   FLAGS & OFFSET (3b + 13b) (2B)
                                0x40,               #   TIME TO LIVE (1B)
                                protocol)           #   PROTOCOL (1B)
        
        ip_header2 = struct.pack('!II',
                                myIP,               #   SOURCE ADDRESS (4B)
                                dstIP)              #   DESTINATION ADDRESS (4B)

        frame_header = ip_header1 + checksum + ip_header2
        if (ipOpts != None):
            frame_header += ipOpts
        frame = frame_header + data

        if (myIP & netmask) == (dstIP & netmask):
            dstMac = ARPResolution(dstIP)
        else:
            dstMac = ARPResolution(defaultGW)

        if dstMac == None:
            logging.debug('ARP devolvió None')
            return False
        
        sendEthernetFrame(frame, len(frame), 0x0800, dstMac)
        i += 1

    IPID += 1

    return True




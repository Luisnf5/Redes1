# Práctica 3: ARP Spoofing y Envío de Datagramas UDP/ICMP

## Descripción General

Esta práctica implementa funcionalidades para el envío y recepción de datagramas UDP e ICMP sobre el protocolo IP, así como la capacidad de realizar ataques de ARP Spoofing. Los principales archivos y sus funcionalidades son los siguientes:

### Archivos Principales

1. **practica3.py**

   - Este archivo es el punto de entrada principal de la práctica.
   - Permite enviar datagramas UDP o mensajes ICMP a una dirección IP destino especificada.
   - Soporta la opción de añadir opciones a los datagramas IP y modificar el contenido de los datos enviados por UDP.
   - Implementa la funcionalidad de ARP Spoofing para enviar respuestas ARP falsas.

2. **udp.py**

   - Implementa funciones necesarias para el nivel UDP.
   - Funciones principales:
     - `getUDPSourcePort()`: Obtiene un puerto origen libre.
     - `process_UDP_datagram()`: Procesa un datagrama UDP recibido.
     - `sendUDPDatagram()`: Construye y envía un datagrama UDP.
     - `initUDP()`: Inicializa el nivel UDP.

3. **icmp.py**

   - Implementa funciones necesarias para el nivel ICMP.
   - Funciones principales:
     - `process_ICMP_message()`: Procesa un mensaje ICMP recibido.
     - `sendICMPMessage()`: Construye y envía un mensaje ICMP.
     - `initICMP()`: Inicializa el nivel ICMP.

4. **ip.py**

   - Implementa funciones necesarias para el nivel IP.
   - Funciones principales:
     - `process_IP_datagram()`: Procesa datagramas IP recibidos.
     - `sendIPDatagram()`: Construye y envía un datagrama IP.
     - `initIP()`: Inicializa el nivel IP.

5. **ethernet.py**

   - Implementa el nivel Ethernet y funciones auxiliares para el envío y recepción de tramas Ethernet.
   - Funciones principales:
     - `process_Ethernet_frame()`: Procesa tramas Ethernet recibidas.
     - `sendEthernetFrame()`: Construye y envía una trama Ethernet.
     - `startEthernetLevel()`: Inicializa el nivel Ethernet.
     - `stopEthernetLevel()`: Detiene el nivel Ethernet.

6. **arp.py**
   - Implementa el protocolo ARP y funciones auxiliares para la resolución de direcciones IP.
   - Funciones principales:
     - `processARPRequest()`: Procesa una petición ARP.
     - `processARPReply()`: Procesa una respuesta ARP.
     - `ARPResolution()`: Realiza una resolución ARP para una IP dada.
     - `ActivateARPSpoofing()`: Activa el ARP Spoofing.
     - `ARPSpoof()`: Envía tramas ARP falsas para realizar ARP Spoofing.

## Funcionalidades Principales

### Recepción de Comandos en `practica3.py`

- **Enviar Ping (ICMP)**

  - Envía un mensaje ICMP Echo Request a la dirección IP destino especificada.
  - Comando: `1`

- **Enviar Datagramas UDP**
  - Envía un datagrama UDP a la dirección IP destino especificada.
  - Comando: `2`

### ARP Spoofing

- **Activar ARP Spoofing**
  - Cuando se activa, se envían respuestas ARP falsas a la dirección IP destino (`dstIP`) con la dirección IP de `ipSpoofed`.
  - Comando: `--spoof <ipSpoofed>`
  - Función: `ActivateARPSpoofing(victimIP, ipSpoofed)`

## Ejecución

Para ejecutar la práctica, se debe utilizar el archivo `practica3.py` con los argumentos necesarios. Ejemplo de uso:

```sh
python3 practica3.py --itf <interfaz> --dstIP <direccion_IP_destino> [opciones] --spoof <ipSpoofed>
```

### Argumentos de `practica3.py`

- `--itf <interfaz>`: Especifica la interfaz de red a utilizar.
- `--dstIP <direccion_IP_destino>`: Especifica la dirección IP destino.
- `--debug`: Activa los mensajes de depuración.
- `--addOptions`: Añade opciones a los datagramas IP.
- `--dataFile <ruta_al_fichero>`: Especifica un fichero con los datos a enviar.
- `--icmpsize <tamaño>`: Especifica el tamaño del payload de ICMP (por defecto es 12).
- `--spoof <ipSpoofed>`: Activa el ARP Spoofing con la dirección IP especificada.

### Ejemplos de Ejecución

#### Sin ARP Spoofing

```sh
H1: python3 practica3.py --itf h1-eth0 --dstIP 10.0.0.2 --debug

H2: python3 practica3.py --itf h2-eth0 --dstIP 10.0.0.1 --debug
```

#### Con ARP Spoofing

```sh
H1: python3 practica3.py --itf h1-eth0 --dstIP 10.0.0.2 --debug

H2: python3 practica3.py --itf h2-eth0 --dstIP 10.0.0.1 --debug

H3: python3 practica3.py --itf h3-eth0 --dstIP 10.0.0.2 --debug --spoof 10.0.0.1
```

from scapy.all import IP, ICMP, send, Raw
from datetime import datetime
import struct, random

def generate_timestamp():
    current_time = datetime.now()
    timestamp = int(current_time.timestamp())
    hex_timestamp = format(timestamp, 'x').zfill(16)
    hex_timestamp_little_endian = ''.join(reversed([hex_timestamp[i:i+2] for i in range(0, len(hex_timestamp), 2)]))
    return bytes.fromhex(hex_timestamp_little_endian)

def create_icmp_packet(dest_ip, identifier, sequence_number, data):

    timestamp_bytes = generate_timestamp()
    
    if len(data.encode('latin-1')) == 1:
        adjusted_data = data.encode('latin-1') + b'\x00' #agregar 0x00 al segundo byte
    else:
        adjusted_data = data.encode('latin-1')[:2]
    
    payload = adjusted_data + bytes.fromhex(
        "000000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    )
    ip_identifier = random.randint(0x0000, 0xFFFF)
    # Crear el paquete ICMP
    icmp_packet = IP(id=ip_identifier,dst=dest_ip, flags='DF')/ICMP(id=identifier, seq=sequence_number)/Raw(timestamp_bytes + payload)
    del icmp_packet[ICMP].chksum
    
    return icmp_packet

def send_icmp(data):
    dest_ip = "8.8.8.8"
    sequence_number = 1
    
    for char in data:
        identifier = 0x0008  
        icmp_packet = create_icmp_packet(dest_ip, identifier, sequence_number, char)
        send(icmp_packet)
        sequence_number += 1

# Función para aplicar el cifrado César
def cesar(text, desp):
    textCesar = ""
    for charC in text:
        if 65 <= ord(charC) <= 90:  # A-Z
            cesarChar = chr((ord(charC) - 65 + desp) % 26 + 65)
        elif 97 <= ord(charC) <= 122:  # a-z
            cesarChar = chr((ord(charC) - 97 + desp) % 26 + 97)
        elif 48 <= ord(charC) <= 57:  # 0-9
            cesarChar = chr((ord(charC) - 48 + desp) % 10 + 48)
        elif ord(charC) == ord(" "):
            cesarChar = " "
        else:
            return -1
        textCesar += cesarChar
    
    return textCesar

# Solicitar el texto y el desplazamiento
inputText = input("Escriba el texto: ")
inputDesp = int(input("Ingrese el desplazamiento para el algoritmo Cesar: "))

# Aplicar el cifrado César
cesarText = cesar(inputText, inputDesp)
if cesarText == -1:
    print("ERROR! HAY CARACTERES ESPECIALES")
else:
    print("Texto cifrado:", cesarText)
    
    # Enviar el texto cifrado como pings ICMP a la dirección 8.8.8.8
    send_icmp(cesarText)

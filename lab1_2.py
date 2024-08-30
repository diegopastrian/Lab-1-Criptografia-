import pyshark

# Función para cargar el diccionario desde un archivo de texto
def cargar_diccionario(ruta_archivo):
    with open(ruta_archivo, 'r', encoding='utf-8') as file:
        diccionario = set(file.read().split())
    return diccionario

# Función para descifrar utilizando el cifrado César (hacia atrás)
def cesar_inverso(text, desp):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) - 65 - desp) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - 97 - desp) % 26 + 97)
        else:
            result += char
    return result

# Función para evaluar la probabilidad de un texto basado en un diccionario
def evaluar_probabilidad(text, diccionario):
    palabras = text.split()
    score = sum(1 for palabra in palabras if palabra.lower() in diccionario)
    return score

# Función para generar todas las combinaciones y evaluarlas
def generar_combinaciones(text, diccionario):
    combinaciones = []
    
    for i in range(26):
        descifrado = cesar_inverso(text, i)
        score = evaluar_probabilidad(descifrado, diccionario)
        combinaciones.append((i, descifrado, score))
    
    # Ordenar las combinaciones por puntaje (de mayor a menor)
    combinaciones_ordenadas = sorted(combinaciones, key=lambda x: x[2], reverse=True)
    
    return combinaciones, combinaciones_ordenadas

# Función para extraer el mensaje cifrado del archivo pcapng
def extract_encrypted_message(pcapng_file):
    # Filtramos los paquetes ICMP
    capture = pyshark.FileCapture(pcapng_file, display_filter='icmp && ip.dst == 8.8.8.8')

    encrypted_message = ""

    for packet in capture:
        if hasattr(packet.icmp, 'data'):
            raw_data = packet.icmp.data.binary_value
            
            # Verificamos que el primer byte sea diferente de 0 y el segundo byte sea 0
            if raw_data[1] == 0x00 and raw_data[0] != 0x00:
                char = raw_data[:1].decode('latin-1', errors='replace')  # Extraemos el primer byte como carácter
                encrypted_message += char

    capture.close()
    return encrypted_message

# Ruta del archivo pcapng
pcapng_file = 'packet_capture.pcapng'

# Cargar el diccionario de palabras en español desde el archivo de texto
ruta_diccionario = 'diccionario_espanol.txt'
diccionario_espanol = cargar_diccionario(ruta_diccionario)

# Utiliza el código que ya tienes para extraer el mensaje cifrado
encrypted_message = extract_encrypted_message(pcapng_file)

# Generar combinaciones y encontrar las más probables
combinaciones, combinaciones_ordenadas = generar_combinaciones(encrypted_message, diccionario_espanol)

# Identificar las mejores combinaciones
mejor_comb = combinaciones_ordenadas[0]

# Imprimir todas las combinaciones en orden de desplazamiento y resaltar las mejores
for i, descifrado, score in combinaciones:
    if descifrado == mejor_comb[1]:
        print(f"\033[92mDesplazamiento {i}: {descifrado} (Mensaje más probable)\033[0m")
    else:
        print(f"Desplazamiento {i}: {descifrado}")

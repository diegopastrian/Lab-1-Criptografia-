from scapy.all import IP, ICMP, send

def send_icmp_text(encryptedText, dest ):
    for charE in encryptedText:
        paquete = IP(dst=dest)/ICMP()/charE
        send(paquete)
        print(f"Se ha enviado: {charE} al destino {dest}.")
    

def cesar(text, desp):
    textCesar="";
    cesarChar = "";
    for charC in text:
        if 65 <= ord(charC) <= 90:  # A-Z
            cesarChar = chr((ord(charC) - 65 + desp) % 26 + 65)
        elif 97 <= ord(charC) <= 122:  # a-z
            cesarChar = chr((ord(charC) - 97 + desp) % 26 + 97)
        elif 48 <= ord(charC) <= 57:  # 0-9
            cesarChar = chr((ord(charC) - 48 + desp) % 10 + 48)
        elif ord(charC)==ord(" "):
            cesarChar = " ";
        else:
            return -1
        textCesar += cesarChar;
    
    return textCesar;

inputText = input("Escriba el texto: ")
inputDesp = int(input("Ingrese el desplazamiento para el algoritmo Cesar: "))
cesarText = cesar(inputText,inputDesp)
if(cesarText == -1):
    print("ERROR! HAY CARACTERES ESPECIALES")
else:
    print("Texto cifrado:", cesar(inputText,inputDesp))
    send_icmp_text(cesarText, "8.8.8.8")
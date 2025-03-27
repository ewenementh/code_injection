You can use payload encryped with xor and encoded with b64. Payload and decryption key are passing as starting arguments. Payload can be encrypted with msfvenom and encoded with certutil. 
Usage:
early.exe "payload" "key"

The payload example is placed in file: payload_calc.txt, word "secret" is key for "dexoring"

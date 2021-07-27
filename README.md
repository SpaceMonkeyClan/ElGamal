# CS4600 - El Gamal Encryption/Decryption Tool

System Specs:

Python Version 3.9.6

pip install pycryptodome


Public and private keys are composed of 3 elements each:

- Kpub = (p, alfa, B)

- Kpriv = (p, alfa, b)

These parameters are:

- p (parameter **-m**): A random integer

- alfa (parameter **-a**): A generator of Zp

- b (parameter **-b**): A secret integer between 2 and (p-2)

- B (parameter **-B**): A public modular exponentiation calculated as B = (alfa^(b))mod(p)


### Encryption

For the encryption process, it is necessary to add **--encrypt**, the parameters of the public key (**-p**, **-a** and **-B**) and the plaintext message (parameter **-m**). The verbose parameter (**-vv**) is optional:

``` 
python main.py --encrypt -p 79 -a 30 -B 59 -m 44 -vv
``` 

![image 1](https://i.imgur.com/mppROiz.jpg)


### Decryption

For the decryption process, it is necessary to add **--decrypt**, the parameters of the private key (**-p**, **-a** and **-b**), the encrypted message (parameter **-m**) and the ephemeral key received with the message (**-ke**). The verbose parameter (**-vv**) is optional:

``` 
python main.py --decrypt -p 79 -a 30 -b 61 -m 73 -ke 13 -vv
``` 

![image 2](https://i.imgur.com/22jplT7.jpg)


### Signature

For the signing process, it is necessary to add **--sign**, the parameters of the private key (**-p**, **-a** and **-b**) and the plaintext message (parameter **-m**). The verbose parameter (**-vv**) is optional:

``` 
python main.py --sign -p 541 -a 128 -b 105 -m 95 -vv
``` 

![image 3](https://i.imgur.com/qeLCIqa.jpg)


### Signature verification

For the signature verification process, it is necessary to add **--verify**, the parameters of the public key (**-p**, **-a** and **-B**), the plaintext message (parameter **-m**) and the signature parameters (**-r** and **-s**):

``` 
python main.py --verify -p 541 -a 128 -B 239 -m 95 -r 280 -s 65 -vv
``` 

![image 4](https://i.imgur.com/ZbjJzK0.jpg)
{"mode":"full","isActive":false}

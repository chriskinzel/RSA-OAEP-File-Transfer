# RSA OAEP File Transfer
This project provides the ability for a server and client program to securely transfer files using a hybrid encryption system that uses 1024 bit RSA with the Optimal Asymmetric Encryption Padding scheme to distribute a 128-bit AES symmetric block cipher key that is then used for encryption and decryption of the file.

# Features
- Secure random generation of safe prime numbers for RSA keys
- Safe decryption key, d > n^0.25
- Small encryption key e = 3 to allow for fast encryption
- Optimized decryption using Chinese remainder theorem
- Implementation of OAEP to prevent attacks on low encryption exponent and other multiplicative attacks
- HMAC message authentication code to ensure authenticity and integrity of data


# Compilation & Running
In project directory  
````javac *.java````  
  
To run on client side  
````java Client [debug] `<hostname>` `<port>`````  
  
To run on server side  
````java Server [debug] `<port>`````

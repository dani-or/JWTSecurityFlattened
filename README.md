# JWTSecurityFlattened
Implementación de JWS y JWE con serialización flattened leyendo las llaves desde archivos .pem con serialización flattened, utilizando la libería 
```sh
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>6.2</version>
</dependency>
```

Vamos a crear 2 clases una emisor(firma y encripta un mensaje) y otra receptor(desencripta y verifica un mensaje) 

## JWS JSON Web Signature RFC 7515(Algoritmo RS256 RSASSA-PKCS-v1_5 using SHA-256)

El resultado puede tener una serialización 

-Compacta(Concatenada con puntos)
```sh
      BASE64URL(UTF8(JWS Protected Header)) || '.' ||
      BASE64URL(JWS Payload) || '.' ||
      BASE64URL(JWS Signature)
```


-Flattened(Formato JSON) 
```sh
    {
      "payload":"<payload contents>",
      "protected":"<integrity-protected header contents>",
      "header":<non-integrity-protected header contents>,
      "signature":"<signature contents>"
     }
```

## JWE JSON Web Encryption RFC 7516(Algoritmo AES_256_CBC_HMAC_SHA_512 )

El resultado puede tener una serialización 

-Compacta(Concatenada con puntos)
```sh
      BASE64URL(UTF8(JWE Protected Header)) || '.' ||
      BASE64URL(JWE Encrypted Key) || '.' ||
      BASE64URL(JWE Initialization Vector) || '.' ||
      BASE64URL(JWE Ciphertext) || '.' ||
      BASE64URL(JWE Authentication Tag)
```


-Flattened(Formato JSON) 
```sh
    {
      "protected":"<integrity-protected header contents>",
      "unprotected":<non-integrity-protected header contents>,
      "header":<more non-integrity-protected header contents>,
      "encrypted_key":"<encrypted key contents>",
      "aad":"<additional authenticated data contents>",
      "iv":"<initialization vector contents>",
      "ciphertext":"<ciphertext contents>",
      "tag":"<authentication tag contents>"
     }
```

### Antes de empezar

Para hacer la prueba debemos tener 2 pares de llaves: 
##### Llaves del emisor 

El emisor es el que va emitir el mensaje y este va tener su par de llaves(pública y privada, y la llave pública del receptor).

 - llave privada (Se usa para firmar el mensaje desde el emisor)
 - llave pública (Se usa para verificar el mensaje desde el receptor)

Creación llave privada del emisor:
```sh
$ openssl genrsa -des3 -out /home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate1.pem 2048
```

Eliminar el passphrase de la llave privada del emisor:
```sh
$ openssl rsa -in /home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate1.pem -out /home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate.pem
```

Obtener la llave pública del emisor:
```sh
$ openssl rsa -in /home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate.pem -outform PEM -pubout -out /home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorpublic.pem
```
##### Llaves del receptor


El receptor es el que va recibir el mensaje y este va tener su par de llaves(pública y privada, y la llave pública del emisor).

 - llave privada (Se usa para desencriptar el mensaje desde el receptor)
 - llave pública (Se usa para encriptar el mensaje desde el emisor)

Creación llave privada del receptor:
```sh
$ openssl genrsa -des3 -out /home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate1.pem 2048
```

Eliminar el passphrase de la llave privada del receptor:
```sh
$ openssl rsa -in /home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate1.pem -out /home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate.pem
```

Obtener la llave pública del receptor:
```sh
$ openssl rsa -in /home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate.pem -outform PEM -pubout -out /home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorpublic.pem
```

package com.dor.jwt_security_flattened;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class EmisorFlattenedSerialization {

    public static void main(String[] args) {
        // 1. leer llave privada del emisor
        // 2. leer llave publica del receptor
        // 3. firmar el mesaje
        // 4. encriptar el string del paso 3
        // 5. El resultado del paso 4 se le pasa al receptor

        // Mensaje a encriptar
        String message = "Hola dani-or flattened";

        try {

            // Inicio: Lectura llave privada del emisor
            String privateEmisorKeyString;
            privateEmisorKeyString = new String(Files.readAllBytes(Paths.get(
                    "/home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorprivate.pem")));

            System.out.println(privateEmisorKeyString);
            RSAKey emisor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(privateEmisorKeyString);

            System.out.println(emisor.getKeyType());
            System.out.println(emisor.isPrivate());
            // Fin: Lectura llave privada del emisor

            // Inicio: Lectura llave publica del receptor
            String publicReceptorKeyString = new String(Files.readAllBytes(Paths
                    .get("/home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorpublic.pem")));
            System.out.println(publicReceptorKeyString);
            RSAKey receptor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(publicReceptorKeyString);

            System.out.println(receptor.getKeyType());
            System.out.println(receptor.isPrivate());
            // Fin: Lectura llave publica del receptor

            // Inicio: Firma
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(emisor.getKeyID()).build(),
                    new JWTClaimsSet.Builder().subject(message)
                            .issueTime(new Date()).issuer("https://c2id.com")
                            .build());

            signedJWT.sign(new RSASSASigner(emisor));

            // Fin: Firma

            // Inicio: Serialización de la firma flattened
            String jwsString = signedJWT.serialize();
            System.out.println(jwsString);

            String[] tokensS = jwsString.split("\\.");
            org.json.JSONObject headS = new org.json.JSONObject().put("kid",
                    receptor.getKeyID());
            org.json.JSONObject flatSigned = new org.json.JSONObject()
                    .put("header", headS).put("payload", tokensS[1])
                    .put("protected", tokensS[0]).put("signature", tokensS[2]);

            System.out.println("Flat firmado" + flatSigned.toString());
            // Fin: Serialización de la firma flattened

            // Inicio: Encripción
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256,
                            EncryptionMethod.A256CBC_HS512).contentType("JWT")
                                    .build(),
                    new Payload(flatSigned.toString()));

            jweObject.encrypt(new RSAEncrypter(receptor));
            // Fin: Encripción

            // Inicio: Serialización de la encripción flattened
            String jweString = jweObject.serialize();
            System.out.println("encriptado " + jweString);

            String[] tokens = jweString.split("\\.");

            org.json.JSONObject head = new org.json.JSONObject().put("kid",
                    receptor.getKeyID());

            org.json.JSONObject flat = new org.json.JSONObject()
                    .put("header", head).put("encrypted_key", tokens[1])
                    .put("protected", tokens[0]).put("iv", tokens[2])
                    .put("ciphertext", tokens[3]).put("tag", tokens[4]);

            System.out.println("Flat encriptado" + flat.toString());
            // Fin: Serialización de la encripción flattened

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}

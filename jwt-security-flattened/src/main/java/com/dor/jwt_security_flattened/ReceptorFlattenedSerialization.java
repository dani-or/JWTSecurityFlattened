package com.dor.jwt_security_flattened;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;
import java.util.Map;

import org.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

public class ReceptorFlattenedSerialization {

    public static void main(String[] args) {
        // 0. parsear el mensaje del emisor a jsonObject (Este mensaje es flat
        // del EmisorFlattenedSerialization.java)
        // 1. leer llave publica del emisor
        // 2. leer llave privada del receptor
        // 2.5 Generar String compacto del jsonObject que recibimos
        // 3. desencriptar
        // 3.5 Generar String compacto de la firma para verificar
        // 4. verificar
        // 5. Imprimir el mensaje real

        try {
            // Inicio: mensaje del emisor
            String flat2 = "{\"ciphertext\":\"dD2MO12dRLxlyK9e2WvsZY3TuoUjkJ_c_aGWD5ZWQF-qKHufBX7XPHaWLNKDyzdSvu8yeUDwAUJDaWCtVhF4mmGgrNC7y_DM35IuHSKn_8oUrxMTR7NnE8kF41ObqxbbyuPc53b1WCvc0JPakz6JNKlM8bMx072YOxvrYgMK1eX4aC6YlOU09Ll_BjZWVdZzy4AS49VcfY5YO6w3n2AV2YqgDoyuPZBPxpc48-YBqwzbv5NliGo5qbFyh70GhZyDJKOBCb46GvV-LUqsI3aphNhdhTxS7pwVj5pF52hLfaQxC3btxMfyG3JaHaBNgBx0_5SmnAx_-itQKfXP1bMDyTKwuJwehXmKo-kt7Co1FJPaULKUTkjrO0j8QD7mqeDHQXVjoFvGRQRYNHezu9_NnGSj-zxJOwq2MO4hjtw_ZsOREqZ4KtrGqhEWVVRKrb5-kS5RXUa6h4v6hQJQi5_CTIQYfWKCEJXrTCLqMCdcwLHd36wCua-dDO2HdoqQCv_3I0Ht_yCo2AMTwnys07sAygeW33jJLQ0piuTKq4S7WwTfU5BE5oPhGhZt-aa-HwLx6HenuNfIpxU0VBLhaY_OOpvARu_7Zg9RfwZEQI_AvX5ML6OqvUXW0tkoTBxd1bFw51CuVP7XdEaw-j3JsChbZqJPvHJhkiMmVxAJC-lsCDBI5173xJLCS9tTy64Lei6M\",\"protected\":\"eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0\",\"encrypted_key\":\"GPRSt_HMYzbBChv_ss8swSf3ksxovWryCq9wWGfbCGHA-rY_DHkHKQm9KbKiac8YM5TmQS2J90yFbg8MO3PvH_Ehh3XUsyk7yZjHH-d-NyQ9YlxzDq1MO4-kMVGVWpOb5X5KPZQS3PWxwC5ZkvNDjrpiQnTdVIyEe84Ny7nrYuPHvQ3kLT3ZCWZdW39kZNZFfHOjwlbqniYSD6Xeh9VfrvH-YGnscHiv9V_h9U81CZMDzgKZb5qbWMGprOWmjZHUqq35fimE3oEu6KCc3BNm6yRSf3HOcwyBbwpIsW7MvfXAOtDmA5Y642PcrFEzERhYbBTfqLrB4HwWGhk73K2Nrg\",\"header\":{},\"tag\":\"xxWZU_FOn9rmxjWjJJkds0VKS1nlCr6Glj43_cP_OLo\",\"iv\":\"25EX98B8C4G6m3MK1LjQfQ\"}";
            JSONObject encryptedJSON = new JSONObject(flat2);
            // Fin: mensaje del emisor

            // Inicio: Lave publica del emisor
            String emisorPublicKey;
            emisorPublicKey = new String(Files.readAllBytes(Paths.get(
                    "/home/danosori/Documents/externos/REDEBAN/myKey/emisorKey/emisorpublic.pem")));
            System.out.println(emisorPublicKey);
            RSAKey emisor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(emisorPublicKey);
            System.out.println(emisor.getKeyType());
            System.out.println(emisor.isPrivate());
            // Fin: Lave publica del emisor

            // Inicio: Lave privada del emisor
            String receptorPrivateKey = new String(Files.readAllBytes(Paths.get(
                    "/home/danosori/Documents/externos/REDEBAN/myKey/receptorKey/receptorprivate.pem")));
            System.out.println(receptorPrivateKey);
            RSAKey receptor = (RSAKey) RSAKey
                    .parseFromPEMEncodedObjects(receptorPrivateKey);
            System.out.println(receptor.getKeyType());
            System.out.println(receptor.isPrivate());
            // Fin: Lave publica del emisor

            // Inicio: Compactar el mensaje que recibimos
            StringBuilder compactEncriptedJWT = new StringBuilder()
                    .append(encryptedJSON.get("protected")).append(".")
                    .append(encryptedJSON.get("encrypted_key")).append(".")
                    .append(encryptedJSON.get("iv")).append(".")
                    .append(encryptedJSON.get("ciphertext")).append(".")
                    .append(encryptedJSON.get("tag"));
            String m = compactEncriptedJWT.toString();
            System.out.println("Compact encrypted " + m);
            // Fin: Compactar el mensaje que recibimos

            // Incio: desencriptar
            EncryptedJWT encryptedJWT;
            encryptedJWT = EncryptedJWT.parse(m);
            encryptedJWT.decrypt(new RSADecrypter(receptor));
            System.out.println("SIGNEDDD " + encryptedJWT.getPayload());

            // Fin: desencriptar (Esto genera un json String del mensaje
            // firmado)

            // Inicio: Compactar el firmado
            JSONObject signedJSON = getJSONObject(
                    encryptedJWT.getPayload().toJSONObject());
            StringBuilder compactSignedJWT = new StringBuilder()
                    .append(signedJSON.get("protected")).append(".")
                    .append(signedJSON.get("payload")).append(".")
                    .append(signedJSON.get("signature"));
            System.out.println("Compact signed " + compactSignedJWT.toString());
            // Fin: Compactar el firmado

            // Inicio: verificar
            SignedJWT signedJWT = SignedJWT.parse(compactSignedJWT.toString());
            System.out.println(signedJWT.verify(new RSASSAVerifier(emisor)));
            // Fin: Verificar

            // Inicio: obtener el mensaje
            System.out.println(signedJWT.getJWTClaimsSet().getSubject());
            System.out.println(signedJWT.getPayload());
            // Fin: obtener el mensaje
            
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (JOSEException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    private static JSONObject getJSONObject(Object any) {

        JSONObject jsonObj;
        Map<String, String> anyMap;

        if (any instanceof Map) {
            anyMap = (Map<String, String>) any;
            jsonObj = new JSONObject(anyMap);
        } else {
            jsonObj = new JSONObject(any);
        }
        return jsonObj;

    }

}

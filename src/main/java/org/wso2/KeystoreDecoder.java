package org.wso2;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
//import org.wso2.carbon.crypto.provider.KeyStoreBasedInternalCryptoProvider;
//
//import javax.crypto.SecretKey;
//import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;




import javax.crypto.Cipher;

public class KeystoreDecoder {
    public static void main(String[] args) throws Exception {

//        String token = "eyJjIjoiZ0drUnJrR0tYWFNvekdqaXpIZjdhclJxUWpVK0xRdU15WnlBMnBCWER1dTZOL1RQQWJEQVRWU2xqdzFDSHdwOGlObDJOUEZIbXdXM29BeEpwRDRHMHJwcTJVK0dSdjBTMWN4a0hUSitwSmRMaEVjOEdyZkJKQWtHZTNqSjBaNnZrdnVHVU15Ump4NUFScXhuWTlpNitVekh0RExwL2ViaUNvREVBQ2JDRlV3ZHRTOVd0clFJblVhQjY5c0swZlNpbGxjUGg1SGRvMzRtUWpVUk9RclRKanhjbEFTQzExYnhxbTNZWHNIY0lRbTM3MjJjbzRlLzRVQVZpK2FDcFJaVVovVG1pMUdwMjRndCtoZ3dJRWJtb3d5Z3JvcXdvMURpaGVjR2JkRGl4a2t1TUJoQnczMi9OZjhDcWVPSTVYb0ZHWE5kODNSZHhBVHZIbnR4SjRsb2xBIiwidCI6IlJTQS9FQ0IvT0FFUHdpdGhTSEExYW5kTUdGMVBhZGRpbmciLCJ0cCI6IjM4NkY5NEIxMzI2NjA1NTQwQUE1RDhDRjUyRUI1QzAxQjNBNUQ1NkMiLCJ0cGQiOiJTSEEtMSIsImFsZyI6IkhTMjU2In0";
//
//        String[] tokenParts = token.split("\\.");
//
//        String decodedPayload= "";
//
//        if (tokenParts.length == 3) {
//            String payload = tokenParts[1];
//            decodedPayload = new String(Base64.getUrlDecoder().decode(payload));
//            System.out.println("Decoded Payload (c value): " + decodedPayload);
//        } else {
//            System.out.println("Invalid JWT token format");
//        }
//
//        String encodedValue = decodedPayload;

        String encodedValue = "lM2eGFwo81+FAtXQI06YF3h1mCQXawmuIBSv6e6lJ7f0Ch+QrqA5KVNabra21+ZNBc2WMPazWQYe149BCOJTB6++cEC6PN/4GmI7At9r9ObDAL28UKO++OH7UFpfoeJ63z0LqL15AYvc5Hm/G1olkwmwLMyRHadX1ulW5pwdFd2mDKN5ydcg+yj4dUtmd8facNKr9YP9OashxtBjlfrQ9AnewbeVS8NAyeuw1clCYI6TAdgEXgg0r9w+PJAVS85VKHZ54Alz9nzlCex21e/f+g0804EEgNOk0FShbNwWYuaI/YVE7Yo0gVdXypvizRltWf+X5Pj1P0LFVNAFH9kUqQ";


//        String encodedValue = "eyJjIjoiYlpwY1l1bHYrOHpGblFjcGpMNkkrNlVQczVTN2VLbnloUGdKbHY2WmptaGxqWTBkcUl1TXhmdjFqLzNHcFpOTFhFc3VhbzhYdU1yM1RrbjJoWGdMWUZEcTBYMERMTjNUMkh4eW0wTWo0NVQydFpCV0Jac1F4TjY1SmlOSS9BbjI5dExJOFBYZ01RT0pHczkwdDRqWkRoOWJCWWFlTU5zc3pkWTVmVmF6M0NoRVNhUUh4c1ZDZXQyMHdyNHdzVFNBYUllVUhQQW1neFdIbllpZ01xaFhBcld0R2xvdnJTM3MycEdvaFZMOXhKc0hNekxXZHplMW9yTkQ0T0Q5aXBKMDF5YVlHbU4yRSt1ZE14dDBDNkcvZzFaWnJ6MVpWOHJwYlZnWWFHOVdmd0grMW9QT0lST1U1dWdqeHd3ZmYzNy9SOThQM1NrYTBKNklsYTFnVmhsUmVnXHUwMDNkXHUwMDNkIiwidCI6IlJTQS9FQ0IvT0FFUHdpdGhTSEExYW5kTUdGMVBhZGRpbmciLCJ0cCI6IjM4NkY5NEIxMzI2NjA1NTQwQUE1RDhDRjUyRUI1QzAxQjNBNUQ1NkMiLCJ0cGQiOiJTSEEtMSJ9";

        // Decode the Base64-encoded value
        byte[] decodedBytes = Base64.getDecoder().decode(encodedValue);



        // Print the byte array
        for (byte b : decodedBytes) {
            System.out.print(b + " ");
        }

//        String encodedValue = "bZpcYulv+8zFnQcpjL6I+6UPs5S7eKnyhPgJlv6ZjmhljY0dqIuMxfv1j/3GpZNLXEsuao8XuMr3Tkn2hXgLYFDq0X0DLN3T2Hxym0Mj45T2tZBWBZsQxN65JiNI/An29tLI8PXgMQOJGs90t4jZDh9bBYaeMNsszdY5fVaz3ChESaQHxsVCet20wr4wsTSAaIeUHPAmgxWHnYigMqhXArWtGlovrS3s2pGohVL9xJsHMzLWdze1orND4OD9ipJ01yaYGmN2E+udMxt0C6G/g1ZZrz1ZV8rpbVgYaG9WfwH+1oPOIROU5ugjxwwff37/R98P3Ska0J6Ila1gVhlReg==";
//        byte[] encryptedBytes = Base64.getDecoder().decode(encodedValue);

        String keystorePath = "/Users/nuwanbuddhikakarunarathna/Documents/TICKETS/MINISTRYOFARMYSUB-360/MYSQLSetup/newkeystore.jks";
        String keystorePassword = "mypassword";
        String privateKeyAlias = "newcert";
        String privateKeyPassword = "mypassword";

        // Load the keystore
        KeyStore keystore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keystore.load(fis, keystorePassword.toCharArray());
        }

//        KeyStoreBasedInternalCryptoProvider n= new KeyStoreBasedInternalCryptoProvider(keystore,"newcert","mypassword");
//
//         byte[] test = n.decrypt(decodedBytes,"RSA/ECB/OAEPwithSHA1andMGF1Padding","BC");


        // Get the private key from the keystore
        Key privateKey = keystore.getKey(privateKeyAlias, privateKeyPassword.toCharArray());

        Certificate pk = keystore.getCertificate("newcert");

        // Create a Cipher object and initialize it with the private key and decryption mode
//        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());


        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");

        cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) privateKey);

        // Decrypt the encrypted byte array
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        // Convert the decrypted bytes to a String
        String decryptedValue1 = new String(decryptedBytes);

        // Print the decrypted value
        System.out.println("Decrypted Value: " + decryptedValue1);



        /*

        adding further code
         */

//        KeyStoreBasedInternalCryptoProvider n= new KeyStoreBasedInternalCryptoProvider(keystore,"newcert","mypassword");
//        n.encrypt(decryptedBytes,"RSA/ECB/OAEPwithSHA1andMGF1Padding","BC");

        try {
            // Provide the decrypted value
            String decryptedValue = decryptedValue1;

            // Provide the encryption algorithm (e.g., AES)
            String encryptionAlgorithm = "RSA/ECB/OAEPwithSHA1andMGF1Padding";

            // Provide the encryption key
//            String encryptionKey = pk.getPublicKey();

            // Convert the decrypted value to bytes
            byte[] decryptedBytes1 = decryptedValue1.getBytes(StandardCharsets.UTF_8);



            // Create a secret key from the encryption key
//            SecretKey secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), encryptionAlgorithm);

            // Initialize the cipher with the encryption algorithm and key
//            Cipher cipher1 = Cipher.getInstance(encryptionAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, pk.getPublicKey());

            // Encrypt the decrypted value
//            byte[] encryptedBytes = cipher.doFinal(decryptedBytes1);
            byte[] encryptedBytes = cipher.doFinal(decryptedBytes1);

            for (byte b : encryptedBytes) {
                System.out.print(b + " ");
            }

            // Base64 encode the encrypted bytes
//            String encryptedValue = Base64.getEncoder().encodeToString(encryptedBytes);
            String encryptedValue = Base64.getEncoder().withoutPadding().encodeToString(encryptedBytes);

            System.out.println("Encrypted Value: " + encryptedValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}


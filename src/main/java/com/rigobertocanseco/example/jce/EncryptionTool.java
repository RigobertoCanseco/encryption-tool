package com.rigobertocanseco.example.jce;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class EncryptionTool {
    private final static Logger logger = LogManager.getLogger(EncryptionTool.class);

    static final class AES {
        public static String[] encrypt(String str) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
                BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("MAX LENGTH KEY AES: " + maxKeyLen);

            keyGenerator.init(256, new SecureRandom());
            cipher.init(Cipher.ENCRYPT_MODE, keyGenerator.generateKey());
            byte[] cipherText2 = cipher.doFinal(str.getBytes("UTF-8"));

            return new String[]{
                    EncryptionTool.bytesToBase64(keyGenerator.generateKey().getEncoded()),
                    EncryptionTool.bytesToBase64(cipherText2)
            };
        }
    }

    /**
     * Agregar un proveedor criptografico
     * @param provider
     */
    public static void addProvider(Provider provider){
        Security.addProvider(provider);
    }

    /**
     * Genera una llave AES 256
     * @return String
     * @throws NoSuchAlgorithmException
     */
    public static String keyGenerator() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, new SecureRandom());

        return EncryptionTool.bytesToBase64(keyGenerator.generateKey().getEncoded());
    }

    /**
     * Genera un par de llaves DSA
     * @return [Privada, Publica]
     * @throws NoSuchAlgorithmException
     */
    public static String[] keyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");

        return new String[] {
                EncryptionTool.bytesToBase64(keyPairGenerator.generateKeyPair().getPrivate().getEncoded()),
                EncryptionTool.bytesToBase64(keyPairGenerator.generateKeyPair().getPublic().getEncoded())
        };
    }

    /**
     * Convierte un array de bytes a un formato Base64
     * @param bytes byte[]
     * @return String
     */
    private static String bytesToBase64(byte[] bytes) {
        return new String(Base64.encodeBase64(bytes));
    }



    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException {
        String text = "hello world";
        System.out.println("Llave simetrica AES-256:" + EncryptionTool.keyGenerator());

        String [] llavesAsimetrica = EncryptionTool.keyPairGenerator();
        System.out.println("Llave asimétrica DSA Privada:" + llavesAsimetrica[0]);
        System.out.println("Llave asimétrica DSA Pública:" + llavesAsimetrica[1]);

        String [] cipherTextAES = EncryptionTool.AES.encrypt(text);
        System.out.println("LLave generada para cifrado AES:" + cipherTextAES[0]);
        System.out.println("Texto cifrado con AES:" + cipherTextAES[1]);
    }


}

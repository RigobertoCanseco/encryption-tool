package com.rigobertocanseco.example.jce;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class EncryptionTool {
    private final static Logger logger = LogManager.getLogger(EncryptionTool.class);

    static class Message {
        private byte[] message;

        public Message(byte[] message){
            this.message = message;
        }

        public Message(String message)  {
            try {
                this.message = message.getBytes("UTF-8");
            } catch (Exception ex) {
                this.message = null;
            }
        }

        public byte[] getMessage() {
            return message;
        }

        public void setMessage(byte[] message) {
            this.message = message;
        }

        public String toBase64() throws EncryptionToolException {
            try {
                return new String(Base64.encodeBase64(this.message));
            }catch (Exception ex){
                throw new EncryptionToolException("Bytes to Base64 failed:" + ex.getMessage(), ex);
            }
        }

        @Override
        public String toString() {
            return "Message{" + "message=" + new String(this.message) + '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof Message)) return false;
            Message message1 = (Message) o;
            return Arrays.equals(getMessage(), message1.getMessage());
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(getMessage());
        }
    }

    static class EncryptionToolException extends Exception{
        public EncryptionToolException(String message, Throwable cause){
            super(message, cause);
        }
    }

    static final class AES {
        /**
         * Cifra un mensaje con el algoritmo AES-256
         * @param key Key
         * @param msg String
         * @return Message message
         * @throws EncryptionToolException Encrypt failed
         */
        public static Message encrypt(Key key, Message msg) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] cipherText2 = cipher.doFinal(msg.getMessage());

                return new Message(cipherText2);
            } catch (Exception ex){
                throw new EncryptionToolException("Encrypt failed:" + ex.getMessage(), ex);
            }

        }

        /**
         * Descifra mensaje
         * @param key Key
         * @param msg Message
         * @return Message
         * @throws EncryptionToolException Decrypt failed
         */
        public static Message decrypt(Key key, Message msg) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] cipherText = cipher.doFinal(msg.getMessage());

                return new Message(cipherText);
            }catch (Exception ex){
                throw new EncryptionToolException("Decrypt failed:" + ex.getMessage(), ex);
            }
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
     * @return SecretKey
     * @throws EncryptionToolException, Key Generator failed
     */
    public static SecretKey keyGenerator() throws EncryptionToolException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, new SecureRandom());
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("MAX LENGTH KEY AES: " + maxKeyLen);

            return keyGenerator.generateKey();
        }catch (Exception ex){
            throw new EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera un par de llaves DSA
     * @return KeyPair
     * @throws EncryptionToolException Key pair generator failed
     */
    public static KeyPair keyPairGenerator() throws EncryptionToolException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");

            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex){
            throw new EncryptionToolException("Key pair generator failed:" + ex.getMessage(), ex);
        }
    }

    public static String toBase64(byte[] bytes) throws EncryptionToolException {
        try {
            return new String(Base64.encodeBase64(bytes));
        }catch (Exception ex){
            throw new EncryptionToolException("Bytes to Base64 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera MD5
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to MD5 failed
     */
    public static Message messageToMD5(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");

            return new Message(messageDigest.digest(message.getMessage()));
        }catch (Exception ex){
            throw new EncryptionToolException("Bytes to MD5 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera SHA-256
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to SHA-256 failed
     */
    public static Message messageToSHA256(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

           return new Message(messageDigest.digest(message.getMessage()));
        }catch (Exception ex){
            throw new EncryptionToolException("Bytes to SHA-256 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera SHA-512
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to ShA-512 failed
     */
    public static Message messageToSHA512(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            byte[] digest = messageDigest.digest(message.getMessage());

            return new Message(digest);
        }catch (Exception ex){
            throw new EncryptionToolException("Bytes to SHA-512 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera HMAC-SHA256
     * @param key Key
     * @param message Message
     * @return Message
     * @throws EncryptionToolException HMAC-SHA256 generator failed
     */
    public static Message generateHmacSHA256(Key key, Message message) throws EncryptionToolException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            byte[] keyBytes   = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
            String algorithm  = "RawBytes";
            SecretKeySpec key2 = new SecretKeySpec(keyBytes, algorithm);
            mac.init(key2);

            return new Message(mac.doFinal(message.getMessage()));
        }catch (Exception ex){
            throw new EncryptionToolException("HMAC-256 generator failed:" + ex.getMessage(), ex);
        }
    }

    public static void main(String[] args) throws EncryptionToolException {
        Message text = new Message("hello world");
        SecretKey secretKey = EncryptionTool.keyGenerator();
        System.out.println("Llave simetrica AES-256:" + EncryptionTool.toBase64(secretKey.getEncoded()));

        KeyPair keyPair = EncryptionTool.keyPairGenerator();
        System.out.println("Llave asimétrica DSA Privada:" + EncryptionTool.toBase64(keyPair.getPrivate().getEncoded()));
        System.out.println("Llave asimétrica DSA Pública:" + EncryptionTool.toBase64(keyPair.getPublic().getEncoded()));

        Message cipherTextAES = EncryptionTool.AES.encrypt(secretKey, text);
        System.out.println("Texto cifrado con AES:" + cipherTextAES.toBase64());

        Message decipherTextAES = EncryptionTool.AES.decrypt(secretKey, cipherTextAES);
        System.out.println("Texto descifrado con AES:" + decipherTextAES);

        Message hmacSHA256 = EncryptionTool.generateHmacSHA256(secretKey, text);
        System.out.println("HmacSHA-256:" + hmacSHA256.toBase64());

    }


}

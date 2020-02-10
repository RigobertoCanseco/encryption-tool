package com.rigobertocanseco.example.jce;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Array;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EncryptionTool {
    private final static Logger logger = LogManager.getLogger(EncryptionTool.class);
    private final static int ITERATIONS = 65536 ;
    private final static int KEY_SIZE = 256;

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

        public String encode64() throws EncryptionToolException {
            try {
                return new String(Base64.encodeBase64(this.message));
            }catch (Exception ex){
                throw new EncryptionToolException("Bytes to Base64 failed:" + ex.getMessage(), ex);
            }
        }

        public String decode64() throws EncryptionToolException {
            try {
                return new String(Base64.decodeBase64(this.message));
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

        public static Message encrypt(Message key, Message iv, Message message) throws EncryptionToolException {
            try {
                Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec secretKeySpec = new SecretKeySpec(key.getMessage(), "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getMessage());

                ci.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
                byte[] cipherMessage = ci.doFinal(message.getMessage());

                return new Message(cipherMessage);
            } catch (Exception ex) {
                throw new EncryptionToolException("Encrypt failed:" + ex.getMessage(), ex);
            }
        }

        /**
         * Cifra un mensaje con el algoritmo AES-256
         *
         * @param key Key
         * @param msg String
         * @return Message message
         * @throws EncryptionToolException Encrypt failed
         */
        public static Message encrypt(Key key, Message msg) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] cipherText = cipher.doFinal(msg.getMessage());

                return new Message(cipherText);
            } catch (Exception ex) {
                throw new EncryptionToolException("Encrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static Message encrypt(Key key, Message iv, Message message) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getMessage());

                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                //AlgorithmParameters params = cipher.getParameters();
                //Message iv_2 = new Message(params.getParameterSpec(IvParameterSpec.class).getIV());

                //System.out.println("IV 1:" + iv.encode64());
                //System.out.println("IV 2:" + iv_2.encode64());

                byte[] ciphertext = cipher.doFinal(message.getMessage());

                return new Message(ciphertext);
            } catch (Exception ex) {
                throw new EncryptionToolException("Encrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static Message encrypt(Message key, Message message) throws EncryptionToolException {
            try {
                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(key.getMessage()).toCharArray(),
                        EncryptionTool.getSalt().getBytes(), ITERATIONS, KEY_SIZE);

                SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

                //generate IV
                byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
                System.out.println("IV 1:" + new Message(iv).encode64());
                byte[] encryptedText = cipher.doFinal(message.getMessage());
                return new Message(encryptedText);
            } catch (Exception ex) {
                throw new EncryptionToolException("Encrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static Message decrypt(Message key, Message iv, Message message) throws EncryptionToolException {
            try {
                Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec secretKeySpec = new SecretKeySpec(key.getMessage(), "AES");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getMessage());

                ci.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                byte[] cipherMessage = ci.doFinal(message.getMessage());

                return new Message(cipherMessage);
            } catch (Exception ex) {
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
                byte[] text = cipher.doFinal(msg.getMessage());

                return new Message(text);
            }catch (Exception ex){
                throw new EncryptionToolException("Decrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static Message decrypt(Key key, Message iv, Message message) throws EncryptionToolException{
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getMessage());
                SecretKeySpec secretKeySpec = new SecretKeySpec(key.getEncoded(), "AES");

                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
                System.out.println("IV:" + iv.encode64());
                System.out.println("IV:" + new Message(ivParameterSpec.getIV()).encode64());
                byte[] text = cipher.doFinal(message.getMessage());

                return new Message(text);
            }catch (Exception ex){
                throw new EncryptionToolException("Decrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static Message decrypt(Message key, Message msg) throws EncryptionToolException {
            try {
                SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(key.getMessage()).toCharArray(),
                        EncryptionTool.getSalt().getBytes(), ITERATIONS, KEY_SIZE);
                SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
                SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

                //decrypt the message
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

                byte[] decryptTextBytes = cipher.doFinal(msg.getMessage());

                return new Message(decryptTextBytes);
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

    public static String getSalt() throws EncryptionToolException {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[20];
            sr.nextBytes(salt);
            return new String(salt);
        } catch (Exception ex){
            throw new EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    public static SecretKey keyByString(String key) {
        return new SecretKeySpec(key.getBytes(), "AES");
    }

    public static SecretKey key(String pass) throws EncryptionToolException {
        try {
            //SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] salt = EncryptionTool.getSalt().getBytes();
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(pass.toCharArray(), salt, ITERATIONS, KEY_SIZE);

            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        }catch (Exception ex){
            throw new EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    public static Message getIV() throws EncryptionToolException {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            return new Message(ivParameterSpec.getIV());
        } catch (Exception ex){
            throw new EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Genera una llave AES 256
     * @return SecretKey
     * @throws EncryptionToolException, Key Generator failed
     */
    public static SecretKey keyGenerator() throws EncryptionToolException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE, new SecureRandom());
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
        } catch (Exception ex) {
            throw new EncryptionToolException("Key pair generator failed:" + ex.getMessage(), ex);
        }
    }

    public static String encode64(byte[] bytes) throws EncryptionToolException {
        try {
            return new String(Base64.encodeBase64(bytes));
        }catch (Exception ex){
            throw new EncryptionToolException("Bytes to Base64 failed:" + ex.getMessage(), ex);
        }
    }

    public static String decode64(byte[] bytes) throws EncryptionToolException {
        try {
            return new String(Base64.decodeBase64(bytes));
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

    public static void main(String[] args) throws Exception {

        Message[] keyAndIV = createKeyAndIV();
        Message key = new Message("jxwxG40lxQ3htc4CkG9wFRss05iY7ykYkgVyX9K7kQk");
        //Message key = keyAndIV[0];
        Message iv = new Message("4qZBAn0PjnwxwEL3Q1oIyA");
        //Message iv =  keyAndIV[1];

        System.out.println("KEY:" + key);
        System.out.println("IV:" + iv);

        Message text = new Message("hello world");
        System.out.println("Mensaje:" + new String(text.getMessage()));

        Message cipherTextAES = EncryptionTool.AES.encrypt(key, iv, text);
        System.out.println("Texto cifrado con AES:" + cipherTextAES.encode64());

        Message decipherTextAES = EncryptionTool.AES.decrypt(key, iv, cipherTextAES);
        System.out.println("Texto descifrado con AES:" + decipherTextAES);


    }

    public static void example() throws EncryptionToolException {
        Message text = new Message("hello world");
        SecretKey secretKey = EncryptionTool.keyGenerator();
        System.out.println("Llave simetrica AES-256:" + EncryptionTool.encode64(secretKey.getEncoded()));

        KeyPair keyPair = EncryptionTool.keyPairGenerator();
        System.out.println("Llave asimétrica DSA Privada:" + EncryptionTool.encode64(keyPair.getPrivate().getEncoded()));
        System.out.println("Llave asimétrica DSA Pública:" + EncryptionTool.encode64(keyPair.getPublic().getEncoded()));

        Message cipherTextAES = EncryptionTool.AES.encrypt(secretKey, text);
        System.out.println("Texto cifrado con AES:" + cipherTextAES.encode64());

        Message decipherTextAES = EncryptionTool.AES.decrypt(secretKey, cipherTextAES);
        System.out.println("Texto descifrado con AES:" + decipherTextAES);

        Message hmacSHA256 = EncryptionTool.generateHmacSHA256(secretKey, text);
        System.out.println("HmacSHA-256:" + hmacSHA256.encode64());

        String salt = EncryptionTool.getSalt();
        System.out.println("Salt:" + EncryptionTool.encode64(salt.getBytes()));

        String pass = EncryptionTool.encode64(secretKey.getEncoded());
        //System.out.println("Pass:" + new String(pass));

        SecretKey myKey = EncryptionTool.key(pass);
        Message iv = EncryptionTool.getIV();
        System.out.println("IV:" + iv.encode64());

        Message cipherTextAES2 = EncryptionTool.AES.encrypt(secretKey, iv, text);
        System.out.println("Texto cifrado con AES 2:" + cipherTextAES2.encode64());

        Message decipherTextAES2 = EncryptionTool.AES.decrypt(secretKey, iv, cipherTextAES2);
        System.out.println("Texto descifrado con AES 2:" + decipherTextAES2);
    }

    public static void ejemplo1() throws EncryptionToolException {
        String pass = "8R4M6262v8EOrCUH9LzI5zXgFjyPC+APfItE7hcixXQ=";

        Message text = new Message("hello world");
        SecretKey myKey = EncryptionTool.key(pass);
        System.out.println("PASS:" + pass);
        System.out.println("KEY:" + EncryptionTool.encode64(myKey.getEncoded()));

        Message iv = EncryptionTool.getIV();
        System.out.println("IV:" + iv.encode64());

        //Message cipherTextAES2 = EncryptionTool.AES.encrypt(myKey, iv, text);
        Message cipherTextAES2 = new Message("JS9+k8jXOWXxs4/LgqpuLQ==");
        //System.out.println("Texto cifrado con AES 2:" + cipherTextAES2.encode64());

        Message decipherTextAES2 = EncryptionTool.AES.decrypt(myKey, iv, cipherTextAES2);
        System.out.println("Texto descifrado con AES 2:" + decipherTextAES2);
    }

    public static void ejemplo2() throws EncryptionToolException {
        Message pass = new Message("8R4M6262v8EOrCUH9LzI5zXgFjyPC+APfItE7hcixXQ=");
        //Message iv = new Message("8R4M6262v8EOrCUH9LzI5zXgFjyPC+APfItE7hcixXQ=");
        Message text = new Message("hello world");
        SecretKey myKey = EncryptionTool.keyGenerator();
        System.out.println("KEY:" + EncryptionTool.encode64(myKey.getEncoded()));
        Message iv = EncryptionTool.getIV();
        System.out.println("IV:" + iv.encode64());

        Message cipherTextAES2 = EncryptionTool.AES.encrypt(pass, text);
        System.out.println("Texto cifrado con AES 2:" + cipherTextAES2.encode64());

        Message decipherTextAES2 = EncryptionTool.AES.decrypt(pass, iv, cipherTextAES2);
        System.out.println("Texto descifrado con AES 2:" + decipherTextAES2);
    }

    public static Message[] createKeyAndIV() throws EncryptionToolException {
        return new Message[] { new Message(EncryptionTool.keyGenerator().getEncoded()), EncryptionTool.getIV() };
    }
}

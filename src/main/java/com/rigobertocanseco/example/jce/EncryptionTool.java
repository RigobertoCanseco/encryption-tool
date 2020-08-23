package com.rigobertocanseco.example.jce;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Encryption Tool
 */
public class EncryptionTool {
    private final static int ITERATIONS = 65536;
    private final static int KEY_SIZE = 256;

    /**
     * Add a cryptography provider
     *
     * @param provider Provider
     */
    public static void addProvider(Provider provider) {
        Security.addProvider(provider);
    }

    /**
     * Generate a key AES
     *
     * @return SecretKey
     * @throws EncryptionToolException, Key Generator failed
     */
    public static SecretKey keyGenerator() throws EncryptionToolException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE, new SecureRandom());
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("MAX LENGTH KEY AES:" + maxKeyLen);

            return keyGenerator.generateKey();
        } catch (Exception ex) {
            throw new EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Generate a pkey pair DSA
     *
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

    /**
     * Encode Base64
     *
     * @param bytes Bytes
     * @return String
     * @throws EncryptionToolException Bytes to Base64 failed
     */
    public static String encode64(byte[] bytes) throws EncryptionToolException {
        try {
            return new String(Base64.encodeBase64(bytes));
        } catch (Exception ex) {
            throw new EncryptionToolException("Bytes to encode64 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Decode Base64
     *
     * @param bytes Bytes
     * @return String
     * @throws EncryptionToolException Bytes to Base64 failed
     */
    public static String decode64(byte[] bytes) throws EncryptionToolException {
        try {
            return new String(Base64.decodeBase64(bytes));
        } catch (Exception ex) {
            throw new EncryptionToolException("Bytes to decode64 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Generate MD5
     *
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to MD5 failed
     */
    public static Message messageToMD5(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");

            return new Message(messageDigest.digest(message.getMessage()));
        } catch (Exception ex) {
            throw new EncryptionToolException("Bytes to MD5 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Generate SHA-256
     *
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to SHA-256 failed
     */
    public static Message messageToSHA256(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

            return new Message(messageDigest.digest(message.getMessage()));
        } catch (Exception ex) {
            throw new EncryptionToolException("Bytes to SHA-256 failed:" + ex.getMessage(), ex);
        }
    }

    /**
     * Generate SHA-512
     *
     * @param message Message
     * @return Message
     * @throws EncryptionToolException Bytes to ShA-512 failed
     */
    public static Message messageToSHA512(Message message) throws EncryptionToolException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            byte[] digest = messageDigest.digest(message.getMessage());

            return new Message(digest);
        } catch (Exception ex) {
            throw new EncryptionToolException("Bytes to SHA-512 failed:" + ex.getMessage(), ex);
        }
    }

    public static void main(String[] args) throws Exception {

        byte[] key = EncryptionTool.AES.getKey();
        byte[] iv = EncryptionTool.AES.getIV();
        byte[] salt = EncryptionTool.AES.getSalt();
        String originalString = "hola";
        System.out.println(EncryptionTool.encode64(key));
        System.out.println(EncryptionTool.encode64(iv));
        System.out.println(EncryptionTool.encode64(salt));
        String encryptedString = EncryptionTool.AES.encrypt(EncryptionTool.encode64(key), EncryptionTool.encode64(iv),
                EncryptionTool.encode64(salt), originalString);
        System.out.println(encryptedString);
        String decryptedString = EncryptionTool.AES.decrypt(EncryptionTool.encode64(key), EncryptionTool.encode64(iv),
                EncryptionTool.encode64(salt), encryptedString);
        System.out.println(decryptedString);

        String[] keyPair = EncryptionTool.RSA.keyPairGenerator();

        String privateKey = keyPair[0];
        String publicKey = keyPair[1];


        System.out.println(privateKey);
        System.out.println(publicKey);
        encryptedString = EncryptionTool.RSA.encrypt(originalString, publicKey);
        System.out.println(encryptedString);
        decryptedString = EncryptionTool.RSA.decrypt(encryptedString, privateKey);
        System.out.println(decryptedString);

    }

    /**
     * Class Exception: Encryption Tool
     */
    public static class EncryptionToolException extends Exception {
        public EncryptionToolException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Class Message
     */
    public static class Message {
        private byte[] message;

        public Message(byte[] message) {
            this.message = Base64.encodeBase64(message);
        }

        public Message(String message) {
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

        public char[] toCharArray() {
            return new String(this.message).toCharArray();
        }

        public String encode64() throws EncryptionToolException {
            try {
                return new String(Base64.encodeBase64(this.message));
            } catch (Exception ex) {
                throw new EncryptionToolException("Bytes to Base64 failed:" + ex.getMessage(), ex);
            }
        }

        public String decode64() throws EncryptionToolException {
            try {
                return new String(Base64.decodeBase64(this.message));
            } catch (Exception ex) {
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

    /**
     * Class AES to encrypt with algorithm AES
     */
    public static final class AES {

        /**
         * Get a Key
         *
         * @return byte[]
         * @throws EncryptionTool.EncryptionToolException Key generator failed
         */
        public static byte[] getKey() throws EncryptionTool.EncryptionToolException {
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(KEY_SIZE, new SecureRandom());
                int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
                System.out.println("MAX LENGTH KEY AES:" + maxKeyLen);

                return keyGenerator.generateKey().getEncoded();
            } catch (Exception ex) {
                throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
            }
        }

        /**
         * Get a salt random
         *
         * @return byte[]
         */
        public static byte[] getSalt() {
            SecureRandom sr = new SecureRandom();// SHA1PRNG
            byte[] salt = new byte[20];
            sr.nextBytes(salt);
            return salt;
        }

        /**
         * Get a IV random
         *
         * @return byte[]
         */
        public static byte[] getIV() {
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);

            return iv;
        }

        /**
         * Encrypt a string with algorithm AES
         *
         * @param secret String
         * @param iv     String
         * @param salt   String
         * @param string String
         * @return Return a String encode64
         * @throws EncryptionToolException AES encrypt failed
         */
        public static String encrypt(String secret, String iv, String salt, String string) throws EncryptionToolException {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(secret.toCharArray(), Base64.decodeBase64(salt.getBytes()), ITERATIONS, KEY_SIZE);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(Base64.decodeBase64(iv.getBytes())));

                return new String(Base64.encodeBase64(cipher.doFinal(string.getBytes("UTF-8"))));
            } catch (Exception ex) {
                throw new EncryptionToolException("AES encrypt failed:" + ex.getMessage(), ex);
            }
        }

        /**
         * Decrypt a string with algorithm AES
         *
         * @param secret String
         * @param iv     String
         * @param salt   String
         * @param string String
         * @return String
         * @throws EncryptionToolException AES decrypt failed
         */
        public static String decrypt(String secret, String iv, String salt, String string) throws EncryptionToolException {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(secret.toCharArray(), Base64.decodeBase64(salt.getBytes()), ITERATIONS, KEY_SIZE);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Base64.decodeBase64(iv.getBytes())));

                return new String(cipher.doFinal(Base64.decodeBase64(string.getBytes())));
            } catch (Exception ex) {
                throw new EncryptionToolException("AES decrypt failed:" + ex.getMessage(), ex);
            }
        }

        /**
         * Genera HMAC-SHA256
         *
         * @param secret  String
         * @param salt    String
         * @param message String
         * @return Message
         * @throws EncryptionToolException HMAC-SHA256 generator failed
         */
        public static String generateHmacSHA256(String secret, String salt, String message) throws EncryptionToolException {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(secret.toCharArray(), Base64.decodeBase64(salt.getBytes()), ITERATIONS, KEY_SIZE);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
                mac.init(secretKey);

                return new String(Base64.encodeBase64(mac.doFinal(message.getBytes("UTF-8"))));
            } catch (Exception ex) {
                throw new EncryptionToolException("HMAC-256 generator failed:" + ex.getMessage(), ex);
            }
        }

    }

    public static final class RSA {

        public static String[] keyPairGenerator() throws EncryptionToolException {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(4096);
                System.out.println("KEY SIZE RSA 4096");
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                return new String[] {
                    new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded())),
                    new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()))
                };
            } catch (Exception ex) {
                throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
            }
        }

        public static String encrypt(String data, String publicKey) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
                return new String(Base64.encodeBase64(cipher.doFinal(data.getBytes("UTF-8"))));
            } catch (Exception ex) {
                throw new EncryptionToolException("RSA encrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static String decrypt(String data, String base64PrivateKey) throws EncryptionToolException {
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(base64PrivateKey));
                return new String(cipher.doFinal(Base64.decodeBase64(data.getBytes("UTF-8"))));
            } catch (Exception ex) {
                throw new EncryptionToolException("RSA decrypt failed:" + ex.getMessage(), ex);
            }
        }

        public static PublicKey getPublicKey(String base64PublicKey) throws EncryptionToolException {
            try {
                return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decodeBase64(base64PublicKey.getBytes())));
            } catch (Exception ex) {
                throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
            }
        }

        public static PrivateKey getPrivateKey(String base64PrivateKey) throws EncryptionToolException {
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.decodeBase64(base64PrivateKey.getBytes())));
            } catch (Exception ex) {
                throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
            }
        }
    }
}
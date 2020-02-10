package com.rigobertocanseco.example.jce;
import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Demo {

    public static byte[] getKey() throws EncryptionTool.EncryptionToolException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, new SecureRandom());
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            System.out.println("MAX LENGTH KEY AES: " + maxKeyLen);

            return keyGenerator.generateKey().getEncoded();
        }catch (Exception ex){
            throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    public static byte[] getSalt() throws EncryptionTool.EncryptionToolException {
        try {
            SecureRandom sr = new SecureRandom();
            byte[] salt = new byte[20];
            sr.nextBytes(salt);
            return salt;
        } catch (Exception ex){
            throw new EncryptionTool.EncryptionToolException("Key generator failed:" + ex.getMessage(), ex);
        }
    }

    public static byte[] getIV(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        return iv;
    }

    public static String encrypt(String string, String iv, String salt, String secret) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), Base64.decodeBase64(salt.getBytes()), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(Base64.decodeBase64(iv.getBytes())));
            return new String(Base64.encodeBase64(cipher.doFinal(string.getBytes("UTF-8"))));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String iv, String salt, String secret) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), Base64.decodeBase64(salt.getBytes()), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Base64.decodeBase64(iv.getBytes())));
            return new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt.getBytes())));
        }
        catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }


    public static void main(String[] args) throws Exception {
        String originalString = "howtodoinjava.com";
        //byte[] key = getKey();
        //byte[] iv = getIV();
        //byte[] salt = getSalt();
        String key = "oszZSZclDg5Uxa04fdoeeofUP7/wFMHzACAJlCEYRNY=";
        String iv = "Y4NjgYGZVobr5iCSQbwAtA==";
        String salt = "gNP4CLPXncPVVAF7gsQF9CQSnt4=";
        String encryptedString = "qJ0wDJpoFQWDMqei+w5LT6v4bjbI6CdSwE8C3FaIbYM=";



        //String encryptedString = Demo.encrypt(originalString, iv, salt, new String(key)) ;
        String decryptedString = Demo.decrypt(encryptedString, iv, salt, new String(key)) ;

        //System.out.println(EncryptionTool.encode64(iv));
        //System.out.println(EncryptionTool.encode64(salt));
        System.out.println(encryptedString);
        System.out.println(decryptedString);
    }

}

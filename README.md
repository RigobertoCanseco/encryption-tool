# Java security technology

The list of security APIs offered in Java is very extensive, as the following list of the main ones shows:
Java Cryptography Architecture (JCA): This API offers support for cryptographic algorithms, including hash-digest and digital-signature support.

Java Cryptographic Extensions (JCE): This API mainly provides facilities for the encryption and decryption of strings and also secret key generation for symmetric algorithms.

Java Certification Path API (CertPath): This API provides comprehensive functionality for integrating the validation and verification of digital certificates into an application.

Java Secure Socket Extension (JSSE): This API provides a standardized set of features to offer support for SSL and TLS protocols, both client and server, in Java.

Java Authentication and Authorization Service (JAAS): This API provides service for authentication and authorization in Java applications. It provides a pluggable system where authentication mechanisms can be plugged in independently to applications.

## Herramienta para cifrados usando Java Cryptography Extension (JCE) 

### Configuarción de JRE 
Agregar el Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files, para poder eliminar la restricción de clave de 128 bits en Java. [(Ver)](https://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml) 


Descargas

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 6](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) (only required for versions before Java 8 u162)

Extraiga los archivos jar del zip y guárdelos en ${java.home}/jre/lib/security/

### Problemas

Posibles problemas y como resolverlos

[Java Security: Illegal key size or default parameters](https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters/6481658#6481658)

[PBKDF2WithHmacSHA256 SecretKeyFactory not available](https://stackoverflow.com/questions/47392965/pbkdf2withhmacsha512-secretkeyfactory-not-available)

### Bibliografía

https://docs.oracle.com/javase/8/docs/technotes/guides/security/index.html
https://link-springer-com.pbidi.unam.mx:2443/chapter/10.1007/978-1-4842-5052-5_1

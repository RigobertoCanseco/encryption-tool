# Herramienta para cifrados usando Java Cryptography Extension (JCE) 

### Configuarción de JRE 
Agregar el Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files, para poder eliminar la restricción de clave de 128 bits en Java. [(Ver)](https://www.javamex.com/tutorials/cryptography/unrestricted_policy_files.shtml) 


Descargas

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 6](http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html)

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 7](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)

[Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files 8](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) (only required for versions before Java 8 u162)

Extraiga los archivos jar del zip y guárdelos en ${java.home}/jre/lib/security/

### Problemas
[Java Security: Illegal key size or default parameters](https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters/6481658#6481658)



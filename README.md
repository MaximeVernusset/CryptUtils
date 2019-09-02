# CryptUtils

CryptUtils is a wrapper library intended to **permit any java object encryption**.  
It provides features of **symmetric** and **asymmetric encryption/decryption**, and **key generation**.  

## 1. Encryptable interface

The goal of this library is to be able to encrypt any object. To perform this, object must be serialized.  
Thus, any object you want to encrypt must **implement the interface Encryptable** (which extends the Serializable interface). You will then have to override the *toString* and equals methods.

`package vernusset.cryptUtils.encryptableObjects`

In order to encrypt primitive types, you must encapsulate them in a class implementing the interface.  
However, as most of encryption needs are about strings, an already existing **EncryptableString** class is available.  

## 2. Symmetric encryption/decryption

Symmetric encryption uses a secret key to encrypt and decrypt.  
To use this encryption mechanism, you can use the **SymmetricEncryptionMethod** class.  

`package vernusset.cryptUtils`

When instantiating this class, you must provide the algorithm you want it to use, and a secret key.  
Available symmetric algorithm is only **AES**, but with three key sizes, enumerated in **SymmetricEncryptionMethod.Algorithm**:

```java
AES_ECB_PKCS5PADDING_128
AES_ECB_PKCS5PADDING_192
AES_ECB_PKCS5PADDING_256
```

Choose secret key size according your needs.  

*__Note__: 128 bits key is considered sufficient until quantum computers become available.*

If you don’t have a secret key yet, one can be generated with the static method *buildSecretKey*, providing it the desired algorithm to use.  
You are then able to encrypt objects, and get the **output base64 encoded or in an array of bytes**.  
Do the opposite to decrypt from base64 or array of bytes, and cast the result to get the original encryptable object.  

## 3. Asymmetric encryption/decryption

Asymmetric encryption uses a key pair of associated private and public keys. Public key is used to encrypt, and private to decrypt.  
To use this encryption mechanism, you can use the **AsymmetricEncryptionMethod** class.  

`package vernusset.cryptUtils`

When instantiating this class, you must provide the algorithm you want it to use, its key pair, and the public key of the correspondent. Correspondent public key can be the same that public key from instance’s key pair, thus instance will be able to encrypt/decrypt objects for itself, rather than two different instances communicating together using two key pairs (depending of your needs).  
Available asymmetric algorithms are three different implementations or **RSA**, with different key sizes, enumerated in **AsymmetricEncryptionMethod.Algorithm**:

```java
RSA_ECB_PKCS1Padding_1024
RSA_ECB_PKCS1Padding_2048
RSA_ECB_PKCS1Padding_3072
RSA_ECB_OAEPWithSHA_1AndMGF1Padding_1024
RSA_ECB_OAEPWithSHA_1AndMGF1Padding_2048
RSA_ECB_OAEPWithSHA_1AndMGF1Padding_3072
RSA_ECB_OAEPWithSHA_256AndMGF1Padding_1024
RSA_ECB_OAEPWithSHA_256AndMGF1Padding_2048
RSA_ECB_OAEPWithSHA_256AndMGF1Padding_3072
```

Choose algorithm and key pair size according your needs.  

*__Note__: recommended asymmetric key size is 2048 bits, considered sufficient until 2030.*  

*__Note__: asymmetric encryption is resource consuming (in terms of performance and storage), and cannot encrypt data whose size exceeds (key length in bits / 8 – 11) bytes. A good practice is then to encrypt data with a symmetric method, and encrypt the secret key with an asymmetric method.*  

If you don’t have an asymmetric key pair yet, one can be generated with the static method *buildKeyPair*, providing it the desired algorithm to use.  
You are then able to encrypt objects, and get the **output base64 encoded or in an array of bytes**.  
Do the opposite to decrypt from base64 or array of bytes, and cast the result to get the original encryptable object.  

## 4. Simple examples of use

Import CryptUtils jar as project dependency to be able to use it.  

### Symmetric

```java
SymmetricEncryptionMethod.Algorithm symmetricAlgo = SymmetricEncryptionMethod.SymmetricAlgorithm.AES_ECB_PKCS5PADDING_128;
//byte[] secretKey = new byte[] {'T','h','e','B','e','s','t','S','e','c','r','e','t','K','e','y'};
EncryptableString stringToEncrypt =  new EncryptableString("String to encrypt");

try {
    SecretKey secretKey = SymmetricEncryptionMethod.buildSecretKey(symmetricAlgo);
    SymmetricEncryptionMethod sem = new SymmetricEncryptionMethod(symmetricAlgo, secretKey);

    String encrypted = sem.encryptToBase64String(stringToEncrypt);
    System.out.println("Encrypted: " + encrypted);

    EncryptableString decrypted = (EncryptableString)sem.decryptFromBase64String(encrypted);
    System.out.println("Decrypted: " + decrypted.getString());
}
catch (Exception e) {
    e.printStackTrace();
}
```

### Asymmetric

```java
AsymmetricEncryptionMethod.Algorithm asymmetricAlgo = AsymmetricEncryptionMethod.AsymmetricAlgorithm.RSA_ECB_PKCS1Padding_2048;
EncryptableString stringToEncrypt =  new EncryptableString("String to encrypt");

try {
    KeyPair keyPair = AsymmetricEncryptionMethod.buildKeyPair(asymmetricAlgo);
    AsymmetricEncryptionMethod aem = new AsymmetricEncryptionMethod(asymmetricAlgo, keyPair, keyPair.getPublic());

    String encrypted = aem.encryptToBase64String(stringToEncrypt);
    System.out.println("Encrypted: " + encrypted);

    EncryptableString decrypted = (EncryptableString)aem.decryptFromBase64String(encrypted);
    System.out.println("Decrypted: " + decrypted.getString());
}
catch (Exception e) {
    e.printStackTrace();
}
```

***For more details and technical comprehension, please refer to Javadoc and unit testing class.***

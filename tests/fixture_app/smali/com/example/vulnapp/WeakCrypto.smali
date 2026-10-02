.class public Lcom/example/vulnapp/WeakCrypto;
.super Ljava/lang/Object;

.method public static run()V
    .registers 6
    const-string v0, "DES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    const-string v0, "AES"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    const-string v0, "SHA-1"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    new-instance v1, Ljava/util/Random;
    invoke-direct {v1}, Ljava/util/Random;-><init>()V
    return-void
.end method

.method public static staticIv()V
    .registers 4
    const-string v0, "0123456789abcdef"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;
    invoke-direct {v1, v0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
    return-void
.end method

.method public static hardKey()V
    .registers 4
    const-string v0, "MySuperSecretKey1"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "AES"
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-void
.end method

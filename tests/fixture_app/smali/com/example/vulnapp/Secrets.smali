.class public Lcom/example/vulnapp/Secrets;
.super Ljava/lang/Object;

.method public static all()V
    .registers 2
    const-string v0, "@@AWS_KEY@@"
    const-string v0, "-----BEGIN RSA PRIVATE KEY-----"
    const-string v0, "@@JWT@@"
    const-string v0, "@@GITHUB_TOKEN@@"
    return-void
.end method

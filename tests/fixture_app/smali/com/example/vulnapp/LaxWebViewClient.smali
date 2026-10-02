.class public Lcom/example/vulnapp/LaxWebViewClient;
.super Landroid/webkit/WebViewClient;

.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    .registers 4
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
    return-void
.end method

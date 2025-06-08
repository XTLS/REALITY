# REALITY

### THE NEXT FUTURE

Server side implementation of REALITY protocol, a fork of package tls in latest [Go](https://github.com/golang/go/commits/master/src/crypto/tls).
For client side, please follow https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go.  

TODO List: TODO

## VLESS-XTLS-uTLS-REALITY example for [Xray-core](https://github.com/XTLS/Xray-core)

[中文](README.md) | English

```json5
{
    "inbounds": [ // Server Inbound Configuration
        {
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "", // Required, execute ./xray uuid to generate, or a string of 1-30 characters
                        "flow": "xtls-rprx-vision" // Optional, if any, client must enable XTLS
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false, // Optional, if true, output debugging information
                    "dest": "example.com:443", // Required, the format is the same as the dest of VLESS fallbacks
                    "xver": 0, // Optional, the format is the same as xver of VLESS fallbacks
                    "serverNames": [ // Required, the acceptable serverName list, does not support * wildcards for now
                        "example.com",
                        "www.example.com"
                    ],
                    "privateKey": "", // Required, execute ./xray x25519 to generate
                    "minClientVer": "", // Optional, minimum client Xray version, format is x.y.z
                    "maxClientVer": "", // Optional, the highest version of client Xray, the format is x.y.z
                    "maxTimeDiff": 0, // Optional, the maximum time difference allowed, in milliseconds
                    "shortIds": [ // Required, the acceptable shortId list, which can be used to distinguish different clients
                        "", // If there is this item, the client shortId can be empty
                        "0123456789abcdef" // 0 to f, the length is a multiple of 2, the maximum length is 16
                    ],
                    // These two limitations below are optional, for rate limiting fallback connections, bytesPerSec's default is 0, which means disabled
                    // It's a detectable pattern, not recommended to be enabled, RANDOMIZE these parameters if you're a web-panel/one-click-script developer
                    "limitFallbackUpload": {
                        "afterBytes": 0, // Start throttling after (bytes)
                        "bytesPerSec": 0, // Base speed (bytes/s)
                        "burstBytesPerSec": 0 // Burst capacity (bytes/s), works only when it is larger than bytesPerSec
                    },
                    "limitFallbackDownload": {
                        "afterBytes": 0, // Start throttling after (bytes)
                        "bytesPerSec": 0, // Base speed (bytes/s)
                        "burstBytesPerSec": 0 // Burst capacity (bytes/s), works only when it is larger than bytesPerSec
                    }
                }
            }
        }
    ]
}
```

REALITY is intented to replace the use of TLS, it can **eliminate the detectable TLS fingerprint on the server side**, while still maintain the forward secrecy, etc. **Guard against the certificate chain attack, thus its security exceeds conventional TLS**
**REALITY can point to other people's websites**, no need to buy domain names, configure TLS server, more convenient to deploy a proxy service. It **achieves full real TLS that is undistingwishable with the specified SNI to the middleman**
  
For general proxy purposes, the minimum standard of the target website: **Websites out of China's GFW, support TLSv1.3 and H2, the domain name is not used for redirection** (the main domain name may be used to redirect to www)
Bonus points: target website IP reside closer to proxy IP (looks more reasonable, and lower latency), handshake messages after Server Hello are encrypted together (such as dl.google.com), OCSP Stapling
Configuration bonus items: **Block the proxy traffic back to China, TCP/80, UDP/443 are also forwarded to target** (REALITY behaves like port forwarding to the observer, the target IP may be better if it is an uncommon choice among REALITY users)

**REALITY can also be used with proxy protocols other than XTLS**, but this is not recommended due to their obvious and already targeted TLS in TLS characteristics
The next main goal of REALITY is "**pre-built mode**", that is, to collect and build the characteristics of the target website in advance, and the next main goal of XTLS is **0-RTT**

```json5
{
    "outbounds": [ // Client outbound configuration
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "", // The domain name or IP of the server
                        "port": 443,
                        "users": [
                            {
                                "id": "", // consistent with the server
                                "flow": "xtls-rprx-vision", // consistent with the server
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false, // Optional, if true, output debugging information
                    "fingerprint": "chrome", // Required, use uTLS library to emulate client TLS fingerprint
                    "serverName": "", // One of the server serverNames
                    "publicKey": "", // The public key corresponding to the private key of the server
                    "shortId": "", // One of the server shortIds
                    "spiderX": "" // The initial path and parameters of the crawler, recommended to be different for each client
                }
            }
        }
    ]
}
```

The REALITY client should receive the "**Temporary Trusted Certificate**" issued by "**Temporary Authentication Key**", but the real certificate of the target website will be received in the following three cases:

1. The REALITY server rejects the Client Hello of the client, and the traffic is redirected to the target website
2. The Client Hello of the client is redirected to the target website by the middleman
3. Man-in-the-middle attack, it may be the help of the target website, or it may be a certificate chain attack

The REALITY client can perfectly distinguish temporary trusted certificates, real certificates, and invalid certificates, and decide the next action:

1. When the temporary trusted certificate is received, the proxy connection is available and everything is business as usual
2. When the real certificate is received, enter the crawler mode (spiderX)
3. When an invalid certificate is received, TLS alert will be sent and the connection will be disconnected

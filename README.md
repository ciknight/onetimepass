## 两步验证

Two-factor Authentication(2FA)
两步验证，2FA提供多种方案完成用户权限鉴定，例如某些网站验证完用户名密码后还需要输入手机收到的校验码才能登陆成功。

##HOTP 和 TOTP

2FA 中使用的是一次性密码 One Time
Password，OPT，也被称为动态密码。OPT有两种策略：计次使用和计时使用。

### HOTP (HMAC-based One Time Password)

基于 Hash-based Message Authentication Code (HMAC) 
的一次性生成算法，是指密钥相关的哈希运算消息认证码，HMAC 利用 MD5、SHA-1
等哈希算法，针对输入的密钥 K 和计数器 C，得到数字验证码。

#### HOTP 运行原理

服务器端会给用户生成密钥 K，并约定起始计数器C。客户端根据 K 和 C
生成校验码，并在用户点击刷新按钮后将计数器加1，同时更新校验码；而服务器端会在每次校验成功后将计数器加一，
这就保证了校验码只能使用一次。但是客户端的刷新并不通知服务器端，很可能出现客户端计数器大于服务器的情况。
所以服务器端验证失败，还会尝试
C+1，如果匹配上了，就更新服务器端的计数器，保证跟客户端步调一致，出于安全考虑，服务器端会设置一个最大值，
并不会无限尝试下去

### TOTP (Time-based One Time Password)

基于时间的一次性密码生成算法。TOTP 算法需要约定一个起始时间戳
TO，以及时间间隔TS。当把时间戳 Now 减去 To，用得到的时间除以TS并取整，可以得到整数TC。
然后根据 HOTP(K, TC)就可以得到数字校验码。

所以 TOTP 在时间间隔内都能通过校验，并不是一次有效。这也解决了 HOTP 计数器同步问题。

## 解决

HOTP 算法实现比较简单，也有很多现成的库。还是自己实现一遍，并且加上QRCode输出，可以方便的在 Web 端使用。

## Ref

- An HMAC-Based One-Time Password Algorithm [https://tools.ietf.org/html/rfc4226](https://tools.ietf.org/html/rfc4226#page-3)
- HMAC: Keyed-Hashing for Message Authentication [https://tools.ietf.org/html/rfc2104](https://tools.ietf.org/html/rfc2104)
- Google Authenticator [https://github.com/google/google-authenticator](https://github.com/google/google-authenticator)

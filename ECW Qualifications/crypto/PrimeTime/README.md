# ECW Qualifications : Prime Time (crypto, 200)

For the Prime Time challenge, we were given an RSA public key and the base64 encoding of an encrypted message.

The goal was, of course, to decrypt the message.

## The challenge

We're given what we believe to be an RSA public key. After pasting the key in a file, we try to view its contents using OpenSSL:

```shell
$ openssl rsa -pubin -in publickey.pem -text
Public-Key: (1023 bit)
Modulus:
    7b:f6:27:fc:de:68:79:78:28:1c:5c:a7:6b:e5:ed:
    f5:63:b0:7f:e0:08:42:89:58:5f:5b:39:df:a8:57:
    c5:a6:ee:27:93:15:11:11:88:2e:67:36:8f:95:01:
    2a:86:66:4c:2c:88:b6:2d:30:45:e2:71:02:d1:cb:
    4f:0a:17:f7:f4:a6:5c:6b:3a:55:5b:e8:77:5d:8b:
    55:60:dc:be:81:89:e7:29:4a:40:1e:90:b5:66:ce:
    b1:9e:3e:04:3f:b7:e3:0c:e4:1c:60:f2:45:3c:55:
    fa:3c:f4:8b:37:bf:50:a7:be:bd:4e:ac:40:76:00:
    af:f4:60:2e:0a:4d:7b:53
Exponent: 11 (0xb)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIGcMA0GCSqGSIb3DQEBAQUAA4GKADCBhgKBgHv2J/zeaHl4KBxcp2vl7fVjsH/g
CEKJWF9bOd+oV8Wm7ieTFRERiC5nNo+VASqGZkwsiLYtMEXicQLRy08KF/f0plxr
OlVb6Hddi1Vg3L6BiecpSkAekLVmzrGePgQ/t+MM5Bxg8kU8Vfo89Is3v1Cnvr1O
rEB2AK/0YC4KTXtTAgEL
-----END PUBLIC KEY-----
```

So yeah, it's a public key (we can see the exponent `e` and the modulus `n`). In order to decrypt the message, we're going to need the corresponding private key.

## Finding the private key

By using [RSACtfTool](https://github.com/Ganapati/RsaCtfTool), we are able to factor `p` and `q` from the public key and automatically compute the private key.

```shell
$ git clone https://github.com/Ganapati/RsaCtfTool && cd RsaCtfTool
$ ./RsaCtfTool.py --publickey ../publickey.pem --privatekey > ../privatekey.pem
$ cd ..
$ cat message | base64 -d > mess.bin
$ openssl rsautl -decrypt -in mess.bin -inkey privatekey.pem
RSA operation error
139765835171480:error:0407109F:rsa routines:RSA_padding_check_PKCS1_type_2:pkcs decoding error:rsa_pk1.c:273:
139765835171480:error:04065072:rsa routines:RSA_EAY_PRIVATE_DECRYPT:padding check failed:rsa_eay.c:602:
```

Unfortunately, OpenSSL doesn't want to decrypt the message. We'll just have to do it ourselves!

We extract the private exponent `d` using OpenSSL:

```shell
$ openssl rsa -in privatekey.pem -text
Private-Key: (1023 bit)
modulus:
    7b:f6:27:fc:de:68:79:78:28:1c:5c:a7:6b:e5:ed:
    f5:63:b0:7f:e0:08:42:89:58:5f:5b:39:df:a8:57:
    c5:a6:ee:27:93:15:11:11:88:2e:67:36:8f:95:01:
    2a:86:66:4c:2c:88:b6:2d:30:45:e2:71:02:d1:cb:
    4f:0a:17:f7:f4:a6:5c:6b:3a:55:5b:e8:77:5d:8b:
    55:60:dc:be:81:89:e7:29:4a:40:1e:90:b5:66:ce:
    b1:9e:3e:04:3f:b7:e3:0c:e4:1c:60:f2:45:3c:55:
    fa:3c:f4:8b:37:bf:50:a7:be:bd:4e:ac:40:76:00:
    af:f4:60:2e:0a:4d:7b:53
publicExponent: 11 (0xb)
privateExponent:
    38:58:9d:d0:08:00:f1:65:29:81:41:63:5f:97:0f:
    12:73:21:ae:7d:1b:06:f8:9c:88:6f:48:da:06:b3:
    88:63:26:6f:14:4f:64:d9:6c:72:2e:ea:41:43:ba:
    b6:3d:17:39:e5:b2:81:5a:5b:c2:ac:bf:01:48:16:
    98:4a:67:fb:b5:fc:4c:31:1a:e8:83:5c:34:b1:d5:
    c4:2e:7a:e6:72:a9:a2:10:f7:44:49:1a:92:bc:d4:
    d1:6b:9c:2d:35:2e:34:f8:08:a7:f0:7b:23:55:de:
    52:e9:78:28:96:90:db:f4:03:88:1a:40:e6:0b:b0:
    5e:a2:7d:23:bf:8b:47:db
prime1:
    00:b2:24:0d:99:32:c4:83:db:9b:51:8d:b9:4a:1a:
    61:c2:a3:f4:81:fb:88:25:44:b9:4a:16:d8:d8:c0:
    03:98:8f:84:0f:35:55:74:be:7b:bf:b6:6e:b7:42:
    e5:c3:0d:1c:c7:75:15:bd:a8:56:61:57:ef:e1:0c:
    d6:18:da:5b:4f
prime2:
    00:b2:24:0d:99:32:c4:83:db:9b:51:8d:b9:4a:1a:
    61:c2:a3:f4:81:fb:88:25:44:b9:4a:16:d8:d8:c0:
    03:98:8f:84:0f:35:55:74:be:7b:bf:b6:6e:b7:42:
    e5:c3:0d:1c:c7:75:15:bd:a8:56:61:57:ef:e1:0c:
    d6:18:da:4e:bd
exponent1:
    71:5c:c2:d5:da:7d:0e:17:62:d6:ce:8d:2f:28:0f:
    aa:68:55:c7:14:6d:e9:2b:bb:ba:c8:b8:89:ee:8d:
    ec:b8:6b:4f:7f:07:d5:ed:94:91:45:8c:46:13:4c:
    64:d9:cc:7e:ed:6a:ed:0e:08:6c:7d:c7:32:1f:70:
    f8:8a:f4:49
exponent2:
    40:c7:4a:c3:58:47:75:c4:38:7a:bf:2c:1a:f2:52:
    18:3b:9e:ba:e7:1a:3c:18:fd:8f:4e:20:4e:d1:75:
    ab:d7:18:bf:b6:4d:9e:d0:e7:2e:70:e2:71:2f:99:
    5e:33:50:48:87:aa:d0:9a:4d:f4:da:28:ae:ed:65:
    20:4f:62:73
coefficient:
    09:22:4e:57:2b:41:20:60:75:fc:25:93:86:2f:a6:
    fb:43:46:87:db:a7:70:2b:b2:a1:12:fd:c0:f8:80:
    bd:c2:4e:9b:6e:0d:0d:8b:1e:87:71:7d:01:70:f9:
    53:1c:1e:31:af:5e:e8:3b:9f:df:eb:73:29:36:5b:
    2a:a4:41:4d
writing RSA key
-----BEGIN RSA PRIVATE KEY-----
MIICWAIBAAKBgHv2J/zeaHl4KBxcp2vl7fVjsH/gCEKJWF9bOd+oV8Wm7ieTFRER
iC5nNo+VASqGZkwsiLYtMEXicQLRy08KF/f0plxrOlVb6Hddi1Vg3L6BiecpSkAe
kLVmzrGePgQ/t+MM5Bxg8kU8Vfo89Is3v1Cnvr1OrEB2AK/0YC4KTXtTAgELAoGA
OFid0AgA8WUpgUFjX5cPEnMhrn0bBviciG9I2gaziGMmbxRPZNlsci7qQUO6tj0X
OeWygVpbwqy/AUgWmEpn+7X8TDEa6INcNLHVxC565nKpohD3REkakrzU0WucLTUu
NPgIp/B7I1XeUul4KJaQ2/QDiBpA5guwXqJ9I7+LR9sCQQCyJA2ZMsSD25tRjblK
GmHCo/SB+4glRLlKFtjYwAOYj4QPNVV0vnu/tm63QuXDDRzHdRW9qFZhV+/hDNYY
2ltPAkEAsiQNmTLEg9ubUY25ShphwqP0gfuIJUS5ShbY2MADmI+EDzVVdL57v7Zu
t0Llww0cx3UVvahWYVfv4QzWGNpOvQJAcVzC1dp9Dhdi1s6NLygPqmhVxxRt6Su7
usi4ie6N7LhrT38H1e2UkUWMRhNMZNnMfu1q7Q4IbH3HMh9w+Ir0SQJAQMdKw1hH
dcQ4er8sGvJSGDueuucaPBj9j04gTtF1q9cYv7ZNntDnLnDicS+ZXjNQSIeq0JpN
9Nooru1lIE9icwJACSJOVytBIGB1/CWThi+m+0NGh9uncCuyoRL9wPiAvcJOm24N
DYseh3F9AXD5UxweMa9e6Duf3+tzKTZbKqRBTQ==
-----END RSA PRIVATE KEY-----
```

## Compute the cleartext

Using GMP we can compute the cleartext `m` by doing `m = c^d mod n`

We get `c` with the following command:

```shell
$ cat mess.bin | xxd -p | tr -d '\n'
```

```c
#include <stdio.h>
#include <gmp.h>

int main()
{
    char *s_d = "38589dd00800f165298141635f970f127321ae7d1b06f89c886f48da06b38863266f144f64d96c722eea4143bab63d1739e5b2815a5bc2acbf014816984a67fbb5fc4c311ae8835c34b1d5c42e7ae672a9a210f744491a92bcd4d16b9c2d352e34f808a7f07b2355de52e978289690dbf403881a40e60bb05ea27d23bf8b47db";
    int ui_e = 11;
    char *s_n = "7bf627fcde687978281c5ca76be5edf563b07fe0084289585f5b39dfa857c5a6ee2793151111882e67368f95012a86664c2c88b62d3045e27102d1cb4f0a17f7f4a65c6b3a555be8775d8b5560dcbe8189e7294a401e90b566ceb19e3e043fb7e30ce41c60f2453c55fa3cf48b37bf50a7bebd4eac407600aff4602e0a4d7b53";
    char *s_c = "15f5e4298b280d24afb554de17a92c9a912f0f2ee557aee184b3250f3a9f6b23ed84e8b31e89143af5f17ceda8eb0bc45c9297a9ab612134d9d13401ddf86cf3beb3e27ada82a7dc17d9df7a7da50cfbba835dac4dd3a6b94aab4c2a8116ecbcf1f4f5c30e20b41c628afa4f41127d04cf3b37236d0169abee46ad47d2e059cc";

    mpz_t d, m, n, e, c;
    mpz_init_set_str(d, s_d, 16);
    mpz_init_set_ui(e, ui_e);
    mpz_init_set_str(n, s_n, 16);
    mpz_init_set_str(c, s_c, 16);
    mpz_init(m);

    mpz_powm(m, c, d, n);
    
    gmp_printf("%Zx\n", m);
}
```

Finally, we can turn this integer into a string using `xxd`:

```shell
$ ./gmp_solve | xxd -r -p
Good! The flag is: ECW{4305d233c9a0cc4a2dd431ab54b9f796}.
```
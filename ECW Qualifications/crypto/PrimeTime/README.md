# ECW Qualifications : Prime Time (crypto, 200)

For the Prime Time challenge, we were given an RSA public key and the base64 encoding of an encrypted message.

The goal was, of course, to decrypt the message.

## Finding the private key

By using [RSACtfTool](https://github.com/Ganapati/RsaCtfTool), we are able to factor p and q from the public key and automatically compute the private key.

```shell
$ git clone https://github.com/Ganapati/RsaCtfTool && cd RsaCtfTool
$ ./RsaCtfTool.py --publickey ../publickey.pem --privatekey > ../privatekey.pem
```

Unfortunately, OpenSSL doesn't want to decrypt the message. We'll just have to do it ourselves!

We extract the private exponent `d` using OpenSSL:

```shell
$ openssl rsa -in privatekey.pem -text
```

## Compute the cleartext

Using GMP we can compute the cleartext `m` by doing `m = c^d mod n`

```c
#include <stdio.h>
#include <gmp.h>

int main()
{
    mpz_t m, d, n, c;
    mpz_init(m);

    mpz_init_set_str(d, "INSERT d HERE", 16);
    mpz_init_set_str(n, "INSERT n HERE", 10);
    mpz_init_set_str(c, "INSERT c HERE", 16);

    mpz_powm(m, c, d, n);

    gmp_printf("%Zx\n", m);

    return 0;
}
```

Finally, we can turn this integer into a string using `xxd`:

```shell
$ echo "cleartext hex" | xxd -r -p
```
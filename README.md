# hasencrypt

A simple [ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-03) (i.e.
[Let's Encrypt](https://letsencrypt.org/)) client in Haskell.

## Building and Installing

To build and install `hasencrypt` with [stack](http://haskellstack.org), just
clone the repository and run

```
$ stack setup
$ stack build
$ stack install
```

## Usage

```
Usage: hasencrypt [OPTION...] domains...

  -D[URL]  --directory-url[=URL]  The ACME directory URL.
                                  If this option is specified without URL, the Let's Encrypt directory is
                                  used. For testing purposes this option can be omitted, in which case the
                                  Let's Encrypt staging directory is used. Note that certificates issued by
                                  the staging environment are not trusted.
                                  
  -w DIR   --webroot=DIR          Path to the webroot for responding to http challenges.
                                  
  -a FILE  --account-key=FILE     The ACME account key.
                                  
  -d FILE  --domain-key=FILE      Key for issuing the certificate.
                                  
  -r FILE  --renew=FILE           An optional certificate that is checked for impending expiration.
                                  If renewal is required the certificate is replaced by a newly issued one.
                                  Otherwise, no action is performed.
                                  
  -h       --head                 Fetch only the leaf certificate and not the full certificate chain.
```

## Examples

* Generating the required private keys, registering a new ACME account and
  creating a certificate for `example.com` and `example.org`:

```
$ openssl genrsa 4096 > account.pem
$ openssl genrsa 4096 > domain.pem
$ hasencrypt -D -w path/to/webroot -a account.pem -d domain.pem example.com example.org > cert.pem
```

* Renewing (replacing) an existing certificate if and only if it will expire
  soon (i.e. in less than a week):

```
$ hasencrypt -D -w path/to/webroot -a account.pem -d domain.pem example.com example.org -r cert.pem
```


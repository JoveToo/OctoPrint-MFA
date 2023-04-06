# OctoPrint Multi Factor Authentication Plugin

## Platform support

This plugin works with most browsers with some 
limitations. For Chrome users, you will need
to make sure you do not have any SSL errors on
your connection to OctoPrint. A guide how to do
that is include below.

Other than security limitations, WebAuthn is
supported on most platforms by all major browsers.

## Installing a CA signed certificate

### Introduction

To solve SSL errors on Chrome, you will need
to configure your OctoPrint server with a CA
signed certificate and you will have to trust
this certificate in your browser.

This guide assumes you are doing this on an 
OctoPi. The commands are mostly the same if
you are using other platforms, except for the
HAProxy settings.

This guides uses OpenSSL to generate the
certificates.

### Generating a CA signed certificate

#### Introduction

In this guide, we assume your octopi instance
is called octopi. This is the default name.

If you changed the hostname, also change it 
everywhere in the guide below. Note that you
will have to browser to your OctoPi with this
name or things will still not work.

#### Creating the CA

First, we will generate a key for our CA. You will
need to enter a password. Do not lose this password,
you will need it later.

    openssl genrsa -aes-128-cbc -out OctoPrintCA.key 4096

Next, we will generate the actual CA certificate.

    openssl req -x509 -new -nodes -key OctoPrintCA.key -sha256 -days 1825 -out OctoPrintCA.crt

Now we have a CA, proceed with generating the certicate.

#### Create the certificate

First, we will generate a secret key for out certificate.
Do not set a password for this key, just press ENTER on 
the prompt.

    openssl genrsa -out octopi.key 4096

Now we need to generate a Certificate Request so our CA
can sign it. You can fill in anything you want on the 
questions, except for the commonName entru, this must
match your octopi hostname, in this guide: octopi

    openssl req -new -key octopi.key -out octopi.csr

Because Chrome requires a SAN extension in the certificate,
we need to create a config file with the settings for this 
extension. Create a file octopi.cnf with the following 
content:

    [ v3_req ]
    basicConstraints       = CA:false
    extendedKeyUsage       = serverAuth
    subjectAltName         = @alt_names

    [ alt_names ]
    DNS.1 = octopi

If your router adds a suffix to your domain names (like
.local), you can add additional lines in the alt_names
section for example:

    DNS.2 = octopi.local

Now we generate the actual certificate from our request and
with the extension defined above:

    openssl x509 -req -in octopi.csr -CA OctoPrintCA.crt -CAkey OctoPrintCA.key -CAcreateserial -out octopi.crt -days 1825 -sha256 -extensions v3_req -extfile octopi.cnf

Now we have a certificate with the necessary extensions.

### Installing the certificate

We need a file with both the certificate and the private key.

    cat octopi.crt octopi.key > octopi.pem

Now we will install this file to be used by HAProxy.

    sudo cp octopi.pem /etc/haproxy/
    sudo cp OctoPrintCA.crt /etc/haproxy/

And we change the config file:

    sudo nano /etc/haproxy/haproxy.cfg

Change the line:

    bind :::443 v4v6 ssl crt /etc/ssl/snakeoil.pem

into:

    bind :::443 v4v6 ssl crt /etc/haproxy/octopi.pem ca-file /etc/haproxy/OctoPrintCA.crt

Now we need to restart haproxy:

    sudo service haproxy restart

And we are done on the OctoPi.

### Importing the CA certificate in your browser

Now we have an OctoPi with a CA signed certificate and
now we must tell our browser that it needs to trust
this certificate.

You will need to google how to do this for your browser.
The Certificate OctoPrintCA.crt must be installed in the
"Trusted Root Certifcate Authorities" Certificate Store.

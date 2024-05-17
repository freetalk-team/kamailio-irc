
# IRC (Internet Relay Chat) module for Kamailio

Based on **IMC** module

## Build

1. Checkout **Kamailio** source

```
git clone https://github.com/kamailio/kamailio.git
```

2. Add **IRC** submodule

```
cd kamailio

git submodule add https://github.com/freetalk-team/kamailio-irc.git src/modules/irc
```

3. Setup build container

- Alpine

```
FROM alpine:3.18

RUN apk add --update \
    make g++ cgdb \
    pkgconf \
    linux-headers \
    bison flex \
    postgresql14-dev \
    json-c-dev \
    libxml2-dev \
    libunistring-dev \
    libevent-dev \
    curl-dev

ENTRYPOINT sh
```

- Debian/Ubuntu

**TODO**

Build the image

```
docker build -t kamailio:5.6.3-alpine .
```

4. Build module

```
docker run -it --rm -v /path/to/kamailio/source:/usr/local/src/kamailio kamailio:5.6.3-alpine sh

cd /usr/local/src/kamailio
make

cd src/modules/irc
make
```

5. Add the module to **Kamailio** installation

```
COPY irc.so /usr/lib/kamailio/modules/irc.so
```


## Donation

We hope you've found our software useful. As a non-profit organization, we rely on the generosity of people like you to continue our mission of creating free/OS software

If you've found our work valuable and would like to support us, please consider making a donation. Your contribution, no matter the size, will make a meaningful difference in the lives of those we serve

Thank you for considering supporting us. Together, we can make a positive impact on our community/world

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XUSKMVK55P35G)

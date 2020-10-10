# wgmgr
A WireGuard networks manager.

## Installation

    python3 setup.py install

## Usage
`wgmgr` is intended to be primarily a command line tool, not a library.  
Currently there is no man page available, so please refer to

    wgmgr -h

for usage instructions.

### Example workflow
*Disclaimer*: Do NOT use the private keys listed here!

`$ wgmgr init MyPrivateNetwork "Some description" 10.8.0.0/24 10.8.0.1 my.server.com:51820`

`$ wgmgr client add r9lJ1vbl0zTwZ8MiwefNAETqEPcOKNKu2Vzm+lU8pwU= -n MyFirstClient`

```
$ wgmgr server dump
[NetDev]
Name = MyPrivateNetwork
Kind = wireguard
Description = Some description

[WireGuard]
ListenPort = 51820
PrivateKey = cFA2i9zd94K9iIstoxg790BYJx1lKK1ok1tjQQKZcGQ=

[WireGuardPeer]
PublicKey = r9lJ1vbl0zTwZ8MiwefNAETqEPcOKNKu2Vzm+lU8pwU=
AllowedIPs = 10.8.0.2/32
```
```
$ wgmgr client dump MyFirstClient
[Interface]
PrivateKey = <your private key>
Address = 10.8.0.2/32

[Peer]
PublicKey = avF6+5FS1/8fTEoEA7tCF0uxWbJb7CtQjfDJl73DWyI=
AllowedIPs = 10.8.0.0/24
Endpoint = my.server.com:51820
```

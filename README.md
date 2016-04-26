# dvpn - Distributed VPN
A multipoint VPN implementation

## Dependencies
- gnutls-devel
- gnutls-utils
- libini_config-devel
- ivykis-devel

### RHEL/CentOS
[EPEL](https://fedoraproject.org/wiki/EPEL) is needed for ivykis-devel.

## Installation

### Makefile
`make install` - will compile and copy dvpn to `/usr/bin`, _dvpn.service_ is added to `/usr/lib/systemd/system`.
> Note:  **no additional** configuration files and keys are generated.

`make test` - compiles dvpn, creates sample configuration files (_client.ini_, _client2.ini_, _server.ini_) with corresponding keys (_client.key_, _client2.key_, _server.key_).

### CentOS

```yum install epel-release```

```yum install gnutls-devel libini_config-devel gnutls-utils ivykis-devel```

```git clone https://github.com/buytenh/dvpn.git && cd dvpn && make && make test```

### Fedora
```dnf install libgnutls-devel libini_config-devel ivykis-devel gnutls-utils```

```git clone https://github.com/buytenh/dvpn.git && cd dvpn && make && make test```

#### Autorun
`systemctl enable dvpn && systemctl start dvpn`

## Usage
`dvpn [-c <config.ini>]` - runs dvpn with configuration specified

`dvpn [--show-key-id-hex <key.pem>]` - shows SHA256 node fingerprint which is used in configuration files

##### Tools

Dvpn package comes with additional tools for administrative purposes. They connect to the local dvpn instance, pull out a copy of its routing database, and dump it in a certain way, they also dump changes as they are recieved.

`dvpn [-c <config.ini>] [--dbmon]` - dumps the bare contents of the LSAs and the diffs

`dvpn [-c <config.ini>] [--rtmon]` - takes a routing table centric view

`dvpn [-c <config.ini>] [--hostmon]` - takes the point of view of a dns server wanting to provise resolving service for the overlay network

## Configuration

### General

`/etc/dvpn.ini` - default configuration location.

`certtool --generate-privkey --rsa --sec-param=high --outfile <filename.key>` - generates private key

### dvpn.ini
`PrivateKey` - path to generated key file

`NodeName` - name of the node used on network

[`server|client|hostname`] - block were information about another peers are specified

`Listen|Connect` - determines role of a an entry, may differ in particular blocks

`PeerFingerprint` - unique fingerprint of peer's key, `./dvpn [--show-key-id <key.pem>]` to view a key

`PeerType` - [peer|transit|customer|ipeer|epeer|dbonly]
- epeer - only exchanges traffic for themselves and their customers
- peer - alias to epeer
- transit - peer is authorized to route traffic for you on your behalf
- customer - peer is allowed use you as a transit
- ipeer - provides transit to each other, they are transit and customer in both directions
- dbonly - peer only exchange LSAs, but no data at all

Route readvertising works basically like most ISPs. Customer routes are propagated to other customers, to transits and to peers while transit and peer routes are only propagated to customers.

From \ To | Customer | Transit | Peer
--- | --- | --- | ---
Customer | YES | YES | YES
Transit | YES | NO | NO
Peer | YES | NO | NO

There are two route types, readvertisable and nonreadvertisable. Readvertisable can be advertised to transits, and then it stays readvertisable, nonreadvertisable can only be advertised to customers, but if you advertise a readvertisable route to a customer or a peer, it thereby becomes nonreadvertisable.

#### Example
Foo node
```
PrivateKey=foo.key
NodeName=foo

[bar]
Listen=0.0.0.0:19275
PeerFingerprint=de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef
PeerType=peer
```

Bar node
```
PrivateKey=bar.key
NodeName=bar

[foo]
Connect=localhost:19275
PeerFingerprint=ba:be:c0:01:ba:be:c0:01:ba:be:c0:01:ba:be:c0:01:ba:be:c0:01:ba:be:c0:01:ba:be:c0:01:ba:be:c0:01
PeerType=peer
```

**Note:** Configuration of Foo node contains fingerprint of Bar node and vice versa.

##### IPv6 Addresses in dvpn

Each node has its own interface _dvpn[0-9]_ since it is underlaying network.

Network part of ip address is a 2001:2f::/32 subset of 2001:20::/28 subnet [ORCHIDv2 RFC7343](https://tools.ietf.org/html/rfc7343).

Host part of IPv6 address is 11-22nd (inclusive) group of fingerprint, each group representing one octet separated by colons, thus makes address unspoofable and cryptographically secure (see example below).

> Example fingerprint: _ba:be:c0:01:ba:be:c0:01:ba:be:**c0:01:ba:be:c0:01:ba:be:c0:01:ba:be**:c0:01:ba:be:c0:01:ba:be:c0:01_

> Example IPv6 address: _2001:2f:**c001:babe:c001:babe:c001:babe**_

## ToDo
- [x] update readme to 'tools' update
- [ ] show-key-id desc
- [ ] mkgraph desc

##### Credits
This project is maintained by [Lennert Buytenhek](https://github.com/buytenh)

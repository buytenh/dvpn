# dvpn - Distributed VPN
A multipoint VPN implementation

## Dependencies
- libgnutls-devel
- libini_config-devel
- ivykis-devel
- gnutls-utils

### RHEL/CentOS
[EPEL](https://fedoraproject.org/wiki/EPEL) is needed for ivykis-devel.

## Installation

### Fedora
```dnf install libgnutls-devel libini_config-devel ivykis-devel gnutls-utils```

```git clone https://github.com/buytenh/dvpn.git && cd dvpn && make && make test```

## Usage
` ./dvpn [-c <config.ini>]` - runs dvpn with configuration specified

`./dvpn [--show-key-id <key.pem>]` - shows SHA256 node fingerprint which is used in configuration files

After compilation sample configs and keys will be created.

## Configuration
`PrivateKey` - path to generated key file

`NodeName` - name of the node used on network

[`server|client|hostname`] - block were information about another peers are stored

`Listen|Connect` - determines role of a an entry, may differ in particular blocks

`PeerFingerprint` - unique fingerprint of peer's key, `./dvpn [--show-key-id <key.pem>]` to view a key

`PeerType` - [peer|transit|customer|ipeer|epeer|transmit|customer|dbonly]
- epeer - only exchanges traffic for themselves and their customers
- peer - alias to epeer
- transit - peer is authorized to route traffic for you on your behalf
- customer - peer is allowed use you as a transit
- ipeer - provides transit to each other, they are transit and customer in both directions
- dbonly - peer only exchange LSAs, but no data at all

Route readvertising works basically like most ISPs. Customer routes are propagated to other customers, to transits and to peers while transit and peer routes are only propagated to customers.

From\To | Customer | Transit | Peer
--- | --- | --- | ---
Customer | YES | YES | YES
Transit | YES | NO | NO
Peer | YES | NO | NO

There are two route types, readvertisable and nonreadvertisable. Readvertisable can be advertised to transits, and then it stays readvertisable, nonreadvertisable can only be advertised to customers, but if you advertise a readvertisable route to a customer or a peer, it thereby becomes nonreadvertisable.

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

### Makefile
`make install` - will compile only dvpn and copy it to `/usr/bin` and dvpn.service to `/usr/lib/systemd/system` note that **no additional** configuration files, keys or tools are created.

`make test` - compiles dvpn with tools in current directory, creates sample configuration files (client.ini, client2.ini, server.ini) with corresponding keys (client.key, client2.key, server.key).

If you would like to generate your own key use `certtool --generate-privkey --rsa --sec-param=high --outfile <filename.key>`.

### Fedora
```dnf install libgnutls-devel libini_config-devel ivykis-devel gnutls-utils```

```git clone https://github.com/buytenh/dvpn.git && cd dvpn && make && make test```

## Usage
` ./dvpn [-c <config.ini>]` - runs dvpn with configuration specified, by default without flag looks for configuration in `/etc/dvpn.ini`

`./dvpn [--show-key-id <key.pem>]` - shows SHA256 node fingerprint which is used in configuration files

## Configuration
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

From\To | Customer | Transit | Peer
--- | --- | --- | ---
Customer | YES | YES | YES
Transit | YES | NO | NO
Peer | YES | NO | NO

There are two route types, readvertisable and nonreadvertisable. Readvertisable can be advertised to transits, and then it stays readvertisable, nonreadvertisable can only be advertised to customers, but if you advertise a readvertisable route to a customer or a peer, it thereby becomes nonreadvertisable.

### Example
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

## Tools
`rtmon`, `topomon` and `hostmon` are tools provided with dvpn package for administrative purposes. They connect to the local dvpn instance, pull out a copy of its routing database, and dump it in a certain way, they also dump changes as they are recieved.

- `./topomon [-c <config.ini>]` - dumps the bare contents of the LSAs and the diffs
- `./rtmon [-c <config.ini>]` - takes a routing table centric view
- `./hostmon [-c <config.ini>]` - takes the point of view of a dns server wanting to provise resolving service for the overlay network

As mentioned above these tools also look for default configuration in `/etc/dvpn.ini` as dvpn itself without flag specified.

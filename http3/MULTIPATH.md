# Automatic multipath discovery

Automatic discovery is owned by the underlying QUIC connection, independently
of HTTP/3. Applications do not need to call `AddPath` or `Probe`.

```go
transport := &http3.Transport{EnableMultipath: true}
defer transport.Close()
client := &http.Client{Transport: transport}
```

The server must also negotiate multipath:

```go
server := &http3.Server{
    Addr: ":443",
    Handler: handler,
    QUICConfig: &quic.Config{EnableMultipath: true, MaxPathID: 4},
}
```

Existing clients using `QUICConfig.EnableMultipath` also receive automatic
discovery. The convenience `Transport.EnableMultipath` option clones the supplied
QUIC configuration and defaults an unset `MaxPathID` to 4. Multipath remains opt-in;
a server that does not support it continues to use ordinary single-path QUIC.

After the handshake, discovery scans addresses on active interfaces immediately
and every two seconds. It excludes the initial route's source address, duplicate
addresses, incompatible IP families, unspecified, multicast and link-local
addresses. Loopback addresses are considered only for loopback destinations.
Each candidate gets a source-bound UDP socket and must pass QUIC path validation
before carrying application traffic. Up to four additional paths are managed,
subject to the peer's path-ID limit.

When an address disappears from a successful inventory, its path is abandoned and
its socket is closed. Inventory errors retain existing paths. Closing the QUIC
connection stops discovery and releases its sockets. A validation
attempt has a two-second deadline; an address that failed validation is not retried
until it disappears and reappears. Path IDs are never reused, so repeated network
changes can exhaust the peer's current path-ID allowance.

## Scope

- Discovery runs for all multipath QUIC client connections, including direct
  `DialAddr`, `DialAddrEarly`, `Dial`, `DialEarly` and `Transport.Dial` users.
  Custom HTTP/3 dialers must pass the desired QUIC configuration. `NewClientConn`
  uses the discovery policy of the supplied QUIC connection; it does not start a
  second discovery worker. Servers validate client-created paths but do not
  initiate discovery.
- Set `QUICConfig.DisableAutomaticPathDiscovery` to manage paths manually.
  `QUICConfig.PathDiscoveryAddresses` optionally supplies candidates instead of
  enumerating OS interfaces. The callback must return promptly and be safe for
  concurrent use by multiple connections. Discovered sockets are owned by QUIC;
  sockets supplied by the application retain their existing ownership rules.
- It discovers local source addresses, not new server addresses. The destination
  stays the same, so IPv4-to-IPv6 alternate destination discovery is not provided.
- Source binding relies on OS routing. It does not force a physical interface or
  guarantee independent links or additional bandwidth.
- The initial route is sampled once. Routing changes without address changes and
  interface-scoped IPv6 link-local paths are not handled by this discovery layer.
- Tests use a controlled interface inventory with real loopback UDP and HTTP/3
  traffic, including late address appearance, removal and unsupported peers.
  They do not establish performance or routing behavior on Wi-Fi plus cellular.

## Direct QUIC clients

```go
conn, err := quic.DialAddr(ctx, address, tlsConfig, &quic.Config{
    EnableMultipath: true,
    MaxPathID: 4,
})
if err != nil {
    return err
}
defer conn.CloseWithError(0, "")
```

Unlike the HTTP/3 convenience flag, `quic.Config.EnableMultipath` does not change
an explicitly zero `MaxPathID`. Configure the path-ID allowance on both peers.
The standard single-use dialers choose non-empty connection IDs for multipath.

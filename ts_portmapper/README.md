# ts_portmapper

Ask the LAN gateway for an inbound UDP mapping with NAT-PMP (RFC 6886) or PCP (RFC 6887), so peers
behind hard NATs can reach this node directly. Modelled on Go Tailscale's `net/portmapper`.

Every packet goes through `GatewayCap`: the only destination is a validated private, on-link
gateway's port 5351, sockets are bound to the host's own address and, where the OS allows it, its
interface, and a policy is checked before each send. UPnP-IGD is not implemented.

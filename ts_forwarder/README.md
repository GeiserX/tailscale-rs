# ts_forwarder

Inbound subnet-router / exit-node forwarding dataplane.

Accepts flows on a dedicated overlay (any-IP) netstack, classifies each
destination against an advertised [`RouteTable`] (subnet route vs. exit-node
default route), and splices the decrypted stream to a real OS socket through a
[`RealDialer`].

Fail-closed and anti-leak by construction: [`DirectDialer`] *structurally*
refuses exit-node egress (the refusal is a type, not a runtime flag), so the
real origin IP can never leak via an accidental direct dial; explicit
exit-node egress is the separate, opt-in [`HostExitDialer`]. Unclassified,
refused, timed-out, and over-capacity flows are dropped, never dialed. IPv4
only on the tailnet (binds `0.0.0.0`, never `::`).

# ts_host_net

Host route + DNS programming for TUN transport mode.

The single host-integration chokepoint (the host-side analogue of
`ts_forwarder`'s `RealDialer`): it programs the routing table and system
resolver, and reverses them on teardown. IPv4-only by construction.

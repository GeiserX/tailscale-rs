# ts_metrics

An in-process client-metrics registry mirroring Go Tailscale's `util/clientmetric`: lightweight
global counters and gauges, incremented on hot paths, exported in Prometheus text exposition
format. Used by the `tailscale` crate to back `Device::metrics()`.

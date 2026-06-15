# ts_netmon

Detect OS network link changes (Wi-Fi switch, sleep/wake, default-route change) and coalesce them
into a single debounced event so the runtime can re-bind and re-probe connectivity.

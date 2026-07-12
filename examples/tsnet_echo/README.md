# Example: tsnet Echo

> [!NOTE]
> See the top-level [Requirements section](../README.md#requirements) for pre-requisites.

The same TCP echo server as [`tcp_echo`](../tcp_echo), but built with the **Go-idiomatic
[`tsnet::Server`](https://docs.rs/geiserx_tailscale/latest/tailscale/tsnet/struct.Server.html)
facade** instead of the native `Config` + `Device` surface. It exists to show the shape a Go `tsnet`
user expects — set the struct's fields, then call a method and let the node start lazily:

```go
// Go tsnet:
srv := &tsnet.Server{Hostname: "tsnet_echo_example", AuthKey: key, Dir: "tsnet_echo_state"}
defer srv.Close()
ln, _ := srv.Listen("tcp", ":1234")
```

```rust
// tailscale-rs tsnet facade (this example):
let mut srv = Server::new();
srv.hostname = Some("tsnet_echo_example".into());
srv.auth_key = Some(key);
srv.dir = Some("tsnet_echo_state".into());
let listener = srv.listen("tcp", ":1234").await?;   // Start() happens lazily on this first call
// … accept connections …
drop(listener);                                     // release the netstack listener before closing
// … srv.close(Some(Duration::from_secs(5))).await;
```

This example requires the **`tsnet`** cargo feature (`--features tsnet`).

Start the example:

```sh
# Terminal 1
$ TS_RS_EXPERIMENT=this_is_unstable_software \
    cargo run --features tsnet --example tsnet_echo -- --auth-key $AUTH_KEY
...
INFO tsnet_echo: listening on the tailnet (press Ctrl-C to shut down) listening_addr=<tailnet IP>:1234
...
```

Then, in another terminal, connect to it with `nc`, type a message, and hit enter:

```sh
# Terminal 2
$ nc <tailnet IP> 1234
hello, tailscale-rs!
hello, tailscale-rs!
```

After hitting enter, you should see your message echoed back to you in netcat! Press `Ctrl-C` in
the first terminal to shut the node down gracefully (Go `Server.Close`).

If you can't connect to the example with netcat, verify the tailnet policy allows your local
machine to connect to the example's tailnet IP address on TCP port 1234.

## How it maps to Go `tsnet.Server`

| This example | Go `tsnet.Server` | Notes |
|---|---|---|
| `srv.hostname = …` | `Server.Hostname` | Requested hostname. |
| `srv.auth_key = …` | `Server.AuthKey` | Also read from `TS_AUTH_KEY`. |
| `srv.control_url = …` | `Server.ControlURL` | Default control server if unset. |
| `srv.dir = Some(…)` | `Server.Dir` | Persists node **identity keys** to `dir/tailscale-rs.state`. |
| `srv.up(timeout)` | `Server.Up(ctx)` | Lazy `Start` + wait until `Running`. |
| `srv.tailscale_ips()` | `Server.TailscaleIPs()` | This node's tailnet addresses. |
| `srv.listen("tcp", ":1234")` | `Server.Listen("tcp", ":1234")` | Returns the overlay `netstack::TcpListener`. |
| `srv.close(timeout)` | `Server.Close()` | Graceful shutdown; consumes the server. |

See the crate's [`tsnet` module docs](https://docs.rs/geiserx_tailscale/latest/tailscale/tsnet/) and
[`docs/TSNET_FACADE_DESIGN.md`](../../docs/TSNET_FACADE_DESIGN.md) for the full field/method mapping.

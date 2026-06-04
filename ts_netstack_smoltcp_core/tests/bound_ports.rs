//! Tests for the read-only `BoundPorts` listener-registry query.

use core::net::SocketAddr;

use smoltcp::time::Instant;

extern crate ts_netstack_smoltcp_core as netcore;

use netcore::{HasChannel, Netstack, Response, TcpListenerHandle, tcp};

/// `BoundPorts` reports exactly the local ports of the explicit listeners that exist, and updates
/// as listeners are opened and closed. It answers without any open listener too (empty).
#[test]
fn bound_ports_tracks_open_and_closed_listeners() -> ts_cli_util::Result<()> {
    ts_cli_util::init_tracing();

    let mut stack = Netstack::new(
        netcore::Config {
            loopback: true,
            ..Default::default()
        },
        Instant::ZERO,
    );
    let channel = stack.command_channel();

    let jh = std::thread::spawn(move || -> ts_cli_util::Result<()> {
        // No listeners yet: empty.
        let Response::TcpListen(tcp::listen::Response::BoundPorts { ports }) =
            channel.request_blocking(None, tcp::listen::Command::BoundPorts)?
        else {
            unreachable!();
        };
        assert!(ports.is_empty(), "expected no bound ports, got {ports:?}");

        let open = |port: u16| -> ts_cli_util::Result<TcpListenerHandle> {
            let Response::TcpListen(tcp::listen::Response::Listening { handle }) = channel
                .request_blocking(
                    None,
                    tcp::listen::Command::Listen {
                        local_endpoint: SocketAddr::from(([0, 0, 0, 0], port)),
                    },
                )?
            else {
                unreachable!();
            };
            Ok(handle)
        };
        let h1 = open(8443)?;
        let _h2 = open(9000)?;

        let Response::TcpListen(tcp::listen::Response::BoundPorts { mut ports }) =
            channel.request_blocking(None, tcp::listen::Command::BoundPorts)?
        else {
            unreachable!();
        };
        ports.sort_unstable();
        assert_eq!(ports, vec![8443, 9000]);

        // Close the first; only the second remains.
        channel.request_blocking(None, tcp::listen::Command::Close { handle: h1 })?;

        let Response::TcpListen(tcp::listen::Response::BoundPorts { ports }) =
            channel.request_blocking(None, tcp::listen::Command::BoundPorts)?
        else {
            unreachable!();
        };
        assert_eq!(ports, vec![9000]);

        Ok(())
    });

    // Drive the stack: each request above is one command. Process commands until the command
    // thread finishes. (Listen/Close/BoundPorts need no device IO.)
    while !jh.is_finished() {
        if let Ok(cmd) = stack.wait_for_cmd_blocking(Some(core::time::Duration::from_millis(50))) {
            stack.process_one_cmd(cmd);
        }
    }
    jh.join().unwrap()?;
    Ok(())
}

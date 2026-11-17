//! Map-poll frame decode: the per-frame work of the live netmap poll.
//!
//! Control answers every map poll with one zstd frame per `MapResponse` (we advertise
//! `Compress = "zstd"`, like Go). Both groups run the crate's own frame path through
//! `NetmapFrameDecoder`, reusing one decoder per fixture as the live poll does:
//!
//! - `netmap_decompress`: zstd decode only, with the crate's window and size limits.
//! - `netmap_state_update`: decompress, then parse the `MapResponse` into a `StateUpdate`.
//!
//! Fixtures are netmap-like JSON (peers with keys, addresses, endpoints, hostnames) built from a
//! fixed-seed PRNG and compressed in setup with `zrip::compress` at level 1, a fast level like the
//! ones control servers use. The frames do not depend on the decoder under test.
//! Throughput counts decompressed bytes.
//!
//! ```text
//! cargo bench -p geiserx_ts_control --bench netmap_decode
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};
use ts_control::{NetmapFrameDecoder, PeerUpdate};

/// zstd level for the fixtures.
const LEVEL: i32 = 1;

/// SplitMix64: small, fixed-seed, deterministic across platforms.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }

    /// A 32-byte key as 64 lowercase hex digits.
    fn key_hex(&mut self) -> String {
        (0..4).map(|_| format!("{:016x}", self.next())).collect()
    }

    fn base64(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..len)
            .map(|_| ALPHABET[self.below(64) as usize] as char)
            .collect()
    }

    fn timestamp(&mut self, year: u32) -> String {
        format!(
            "{year}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            1 + self.below(12),
            1 + self.below(28),
            self.below(24),
            self.below(60),
            self.below(60)
        )
    }
}

const TAILNET: &str = "tail4c2e1.ts.net";
const HOST_WORDS: &[&str] = &[
    "build", "ci", "db", "dev", "edge", "gpu", "laptop", "nas", "pi", "prod", "proxy", "relay",
    "runner", "staging", "web", "worker",
];
const OSES: &[&str] = &[
    "linux", "linux", "linux", "macOS", "windows", "iOS", "android",
];
const TAGS: &[&str] = &["tag:server", "tag:ci", "tag:prod", "tag:exit", "tag:k8s"];
const DERP_REGIONS: &[(&str, &str, f64, f64)] = &[
    ("nyc", "New York City", 40.71, -74.0),
    ("sfo", "San Francisco", 37.77, -122.42),
    ("sin", "Singapore", 1.29, 103.85),
    ("fra", "Frankfurt", 50.11, 8.68),
    ("syd", "Sydney", -33.87, 151.21),
    ("lhr", "London", 51.51, -0.13),
    ("sao", "Sao Paulo", -23.55, -46.63),
    ("blr", "Bangalore", 12.97, 77.59),
    ("tok", "Tokyo", 35.68, 139.69),
    ("sea", "Seattle", 47.61, -122.33),
    ("ord", "Chicago", 41.88, -87.63),
    ("dfw", "Dallas", 32.78, -96.8),
    ("par", "Paris", 48.86, 2.35),
    ("mad", "Madrid", 40.42, -3.7),
    ("hkg", "Hong Kong", 22.32, 114.17),
    ("jnb", "Johannesburg", -26.2, 28.05),
    ("waw", "Warsaw", 52.23, 21.01),
    ("dxb", "Dubai", 25.2, 55.27),
    ("tor", "Toronto", 43.65, -79.38),
    ("hnl", "Honolulu", 21.31, -157.86),
];

fn ipv4(rng: &mut Rng) -> String {
    format!(
        "{}.{}.{}.{}",
        1 + rng.below(223),
        rng.below(256),
        rng.below(256),
        1 + rng.below(254)
    )
}

fn tailnet_v4(id: u64) -> String {
    format!(
        "100.{}.{}.{}",
        64 + (id >> 16) % 64,
        (id >> 8) % 256,
        id % 256
    )
}

fn tailnet_v6(id: u64) -> String {
    format!("fd7a:115c:a1e0::{:x}:{:x}", id >> 16, id & 0xffff)
}

/// One peer as control sends it in `Peers` / `PeersChanged`.
fn peer(rng: &mut Rng, id: u64, users: &[u64]) -> Value {
    let host = format!("{}-{}", rng.pick(HOST_WORDS), rng.below(1000));
    let os = rng.pick(OSES);
    let region = 1 + rng.below(DERP_REGIONS.len() as u64);
    let v4 = tailnet_v4(id);
    let v6 = tailnet_v6(id);

    let mut endpoints = vec![format!("{}:41641", ipv4(rng))];
    for _ in 0..rng.below(3) {
        endpoints.push(format!(
            "192.168.{}.{}:41641",
            rng.below(256),
            1 + rng.below(254)
        ));
    }
    if rng.below(2) == 0 {
        endpoints.push(format!(
            "[2001:db8:{:x}::{:x}]:41641",
            rng.below(0x10000),
            rng.below(0x10000)
        ));
    }

    let mut allowed_ips = vec![format!("{v4}/32"), format!("{v6}/128")];
    let mut primary_routes = Vec::new();
    if rng.below(20) == 0 {
        let route = format!("10.{}.0.0/16", rng.below(256));
        allowed_ips.push(route.clone());
        primary_routes.push(route);
    }

    let tags = (rng.below(3) == 0).then(|| vec![rng.pick(TAGS)]);
    let ssh_host_keys = (os == "linux").then(|| {
        vec![
            format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{}", rng.base64(43)),
            format!(
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY{}",
                rng.base64(108)
            ),
        ]
    });
    let online = rng.below(4) != 0;

    json!({
        "ID": id,
        "StableID": format!("n{}CNTRL", rng.base64(12).replace(['+', '/'], "x")),
        "Name": format!("{host}.{TAILNET}."),
        "User": users[rng.below(users.len() as u64) as usize],
        "Key": format!("nodekey:{}", rng.key_hex()),
        "KeyExpiry": rng.timestamp(2027),
        "Machine": format!("mkey:{}", rng.key_hex()),
        "DiscoKey": format!("discokey:{}", rng.key_hex()),
        "Addresses": [format!("{v4}/32"), format!("{v6}/128")],
        "AllowedIPs": allowed_ips,
        "Endpoints": endpoints,
        "HomeDERP": region,
        "DERP": format!("127.3.3.40:{region}"),
        "Hostinfo": {
            "OS": os,
            "Hostname": host,
            "Services": [
                {"Proto": "peerapi4", "Port": 30000 + rng.below(30000)},
                {"Proto": "peerapi6", "Port": 30000 + rng.below(30000)},
            ],
            "sshHostKeys": ssh_host_keys,
        },
        "Created": rng.timestamp(2025),
        "Cap": 110 + rng.below(20),
        "Tags": tags,
        "PrimaryRoutes": primary_routes,
        "LastSeen": (!online).then(|| rng.timestamp(2026)),
        "Online": online,
        "MachineAuthorized": true,
        "CapMap": {
            "https://tailscale.com/cap/file-sharing-target": null,
            "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000": null,
        },
    })
}

fn derp_map(rng: &mut Rng) -> Value {
    let regions: serde_json::Map<String, Value> = DERP_REGIONS
        .iter()
        .zip(1u64..)
        .map(|(&(code, name, lat, lon), id)| {
            let nodes: Vec<Value> = ["a", "b", "c", "d"]
                .iter()
                .map(|suffix| {
                    let ipv6 = format!(
                        "2001:db8:{:x}::{:x}",
                        rng.below(0x10000),
                        rng.below(0x10000)
                    );
                    json!({
                        "Name": format!("{id}{suffix}"),
                        "RegionID": id,
                        "HostName": format!("derp{id}{suffix}.tailscale.com"),
                        "IPv4": ipv4(rng),
                        "IPv6": ipv6,
                        "CanPort80": true,
                    })
                })
                .collect();
            let region = json!({
                "RegionID": id,
                "RegionCode": code,
                "RegionName": name,
                "Latitude": lat,
                "Longitude": lon,
                "Nodes": nodes,
            });
            (id.to_string(), region)
        })
        .collect();
    json!({ "Regions": regions })
}

/// A full netmap: the first `MapResponse` of a map session.
fn full_netmap(seed: u64, peers: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let users: Vec<u64> = (0..peers.div_ceil(4).max(1))
        .map(|_| 1_000_000 + rng.below(9_000_000_000))
        .collect();
    let mut self_node = peer(&mut rng, 1, &users);
    self_node["Online"] = Value::Null;
    let peer_list: Vec<Value> = (2..peers + 2)
        .map(|id| peer(&mut rng, id, &users))
        .collect();

    let admins: Vec<String> = (2..peers / 10 + 3)
        .flat_map(|id| [tailnet_v4(id), tailnet_v6(id)])
        .collect();
    let profiles: Vec<Value> = users
        .iter()
        .enumerate()
        .map(|(i, id)| {
            json!({
                "ID": id,
                "LoginName": format!("user{i}@example.com"),
                "DisplayName": format!("User {i}"),
                "ProfilePicURL": format!("https://avatars.example.com/u/{id}?v=4"),
            })
        })
        .collect();

    let map_response = json!({
        "MapSessionHandle": format!("{:016x}-{:016x}", rng.next(), rng.next()),
        "Seq": 1,
        "Node": self_node,
        "DERPMap": derp_map(&mut rng),
        "Peers": peer_list,
        "DNSConfig": {
            "Routes": { format!("{TAILNET}."): null },
            "Domains": [TAILNET],
            "Proxied": true,
            "ExitNodeFilteredSet": [".ts.net", ".tailscale.net"],
        },
        "Domain": TAILNET,
        "CollectServices": true,
        "PacketFilter": [
            {
                "SrcIPs": admins,
                "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}],
            },
            {
                "SrcIPs": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
                "DstPorts": [
                    {"IP": "*", "Ports": {"First": 22, "Last": 22}},
                    {"IP": "*", "Ports": {"First": 80, "Last": 80}},
                    {"IP": "*", "Ports": {"First": 443, "Last": 443}},
                ],
            },
        ],
        "UserProfiles": profiles,
        "SSHPolicy": {"rules": []},
        "ControlTime": "2026-11-17T12:00:00Z",
    });
    serde_json::to_vec(&map_response).expect("serialize full netmap")
}

/// A small incremental update: one changed peer, a few patches and online flips.
fn delta_update(seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let users = [4_242_424_242];
    let changed = peer(&mut rng, 57, &users);
    let patches: Vec<Value> = [12, 31, 88]
        .iter()
        .map(|id| {
            json!({
                "NodeID": id,
                "DERPRegion": 1 + rng.below(DERP_REGIONS.len() as u64),
                "Endpoints": [format!("{}:41641", ipv4(&mut rng)), "192.168.1.20:41641"],
            })
        })
        .collect();
    let map_response = json!({
        "Seq": 42,
        "PeersChanged": [changed],
        "PeersChangedPatch": patches,
        "OnlineChange": {"12": true, "31": false, "44": true, "90": true},
        "PeerSeenChange": {"31": false, "44": true},
    });
    serde_json::to_vec(&map_response).expect("serialize delta update")
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

struct Fixture {
    name: &'static str,
    json: Vec<u8>,
    frame: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    // (name, JSON, peers expected in the decoded update)
    let raw = [
        ("delta_update", delta_update(0x5eed_0001), 1),
        ("full_100_peers", full_netmap(0x5eed_0100, 100), 100),
        ("full_500_peers", full_netmap(0x5eed_0500, 500), 500),
    ];
    raw.into_iter()
        .map(|(name, json, peers)| {
            let frame = zrip::compress(&json, LEVEL).expect("compress fixture");
            // The FNV-1a digest shows whether two runs decoded the same input.
            eprintln!(
                "fixture {name}: {} B JSON -> {} B zstd ({:.1}x), frame fnv1a {:016x}",
                json.len(),
                frame.len(),
                json.len() as f64 / frame.len() as f64,
                fnv1a(&frame)
            );

            // Check that the fixture round-trips and parses fully, so a bad fixture fails here
            // instead of benchmarking an early error return.
            let mut decoder = NetmapFrameDecoder::default();
            assert_eq!(decoder.decompress(&frame).as_deref(), Some(json.as_slice()));
            let update = decoder.state_update(&frame).expect("fixture parses");
            let decoded_peers = match update.peer_update {
                Some(PeerUpdate::Full(nodes)) => nodes.len(),
                Some(PeerUpdate::Delta { upsert, .. }) => upsert.len(),
                None => 0,
            };
            assert_eq!(decoded_peers, peers, "{name}: decoded peer count");

            Fixture { name, json, frame }
        })
        .collect()
}

fn bench_netmap_decode(c: &mut Criterion) {
    let fixtures = fixtures();

    let mut group = c.benchmark_group("netmap_decompress");
    for fixture in &fixtures {
        group.throughput(Throughput::Bytes(fixture.json.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(fixture.name),
            &fixture.frame,
            |b, frame| {
                let mut decoder = NetmapFrameDecoder::default();
                b.iter(|| decoder.decompress(black_box(frame)).expect("decompress"));
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("netmap_state_update");
    for fixture in &fixtures {
        group.throughput(Throughput::Bytes(fixture.json.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(fixture.name),
            &fixture.frame,
            |b, frame| {
                let mut decoder = NetmapFrameDecoder::default();
                b.iter(|| {
                    decoder
                        .state_update(black_box(frame))
                        .expect("state update")
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_netmap_decode);
criterion_main!(benches);

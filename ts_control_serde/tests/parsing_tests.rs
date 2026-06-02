#![allow(missing_docs)]

use ts_control_serde::{MapResponse, Node};

#[test]
fn test_map_response_parse() {
    const TEST_MAP_RESPONSE: &str = include_str!("data/map_response.json");

    let resp = serde_json::from_str::<MapResponse>(TEST_MAP_RESPONSE)
        .expect("could not parse MapResponse");
    println!("{resp:#?}");
}

#[test]
fn test_node_parse() {
    const TEST_NODE: &str = include_str!("data/node.json");

    let node = serde_json::from_str::<Node>(TEST_NODE).expect("could not parse Node");
    println!("{node:#?}");
}

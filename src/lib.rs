#![crate_name="rand_num_consensus"]
//! ## rand_num_consensus
//!
//! **Decentralized, asynchronous random number consensus.**
//!
//! A group of nodes each choose a random `[u8; 32]`, encrypt it (with an ephemeral key) and sign it,
//! come to consensus on the list of these ciphertexts, then reveal their secret keys and
//! combine the plaintexts. This way, nodes can pledge their choice without allowing
//! any other single node to manipulate the consensus.
//!
//!
//! # Usage
//!
//! High-level users will be most interested in the `NodeLocal` struct, which automatically handles almost the entire protocol,
//! but connections and `Message`s can also be handled manually with `NodeDown` and `NodeUp` (see [`NodeDown`]). The general workflow, for each node, is outlined below.
//!
//! 1. Call `NodeDown::default()` and mutate `identity_key` with a signing key and `address` with a socket address.
//! 2. Call `NodeLocal::new()` using a signing key, socket address, and the list of offline nodes created in the previous step, except the one that refers
//! to this node.
//! 3. Call `.connect_all()` to open connections between each node (**note:** in the future not all nodes will have to be connected).
//! 4. Call `.wait_for_consensus()` to get a random number from the node ring.
//!
//! # Example
//! ```
//! use std::thread;
//! use std::time::Duration;
//! use std::default::Default;
//! use std::net::ToSocketAddrs;
//! use ed25519_dalek::{SigningKey, Signature, VerifyingKey, Signer, Verifier};
//! use rand::random;
//!
//! use rand_num_consensus::{Node, NodeLocal, NodeDown, SharedNonce, Consensus};
//!
//! // Be careful with this, connections scale quadradically
//! const NUM_OF_NODES: u16 = 7;
//! // Update the state of the NodeLocal object every 50 milliseconds during wait_for_consensus()
//! const TICK_RATE: u64 = 50;
//! // Timeout after 45 seconds during wait_for_consensus()
//! const TIMEOUT: u64 = 45000;
//! // Specifies the minimum number of identical lists across nodes required to broadcast
//! // a reveal key.
//! const MAX_MISSING_LISTS: usize = 0;
//!
//! // Create a new identifier for this consensus
//! let shared_nonce: SharedNonce = rand::random::<[u8; 16]>();
//!
//! let mut nodes = Vec::<(NodeDown, SigningKey)>::new();
//! for i in 0..NUM_OF_NODES {
//!    // Create some nodes to connect to
//!    let mut remote_node: NodeDown = Default::default();
//!    let secret_key = SigningKey::from(random::<[u8; 32]>());
//!    remote_node.identity_key = secret_key.verifying_key();
//!    remote_node.address = format!("127.0.0.1:{:?}", 30017 + i*153)
//!       .as_str()
//!       .to_socket_addrs()
//!       .unwrap()
//!       .next()
//!       .unwrap();
//!
//!    nodes.push((remote_node, secret_key));
//! }
//!
//! // Use threads to simulate different computers
//! let mut handles = Vec::<thread::JoinHandle<_>>::new();
//! for (i, (node, secret_key)) in nodes.iter().enumerate() {
//!    // Remove yourself from the list of offline nodes
//!    let mut nodes_wo_self = nodes.clone();
//!    let me = nodes_wo_self.remove(i);
//!    let nodes_wo_self = nodes_wo_self
//!       .iter()
//!       .cloned()
//!       .map(|(node, secret_key)| node)
//!       .collect();
//!
//!    // Start a node on a new thread
//!    let mut local_node = NodeLocal::new(secret_key.clone(), node.address(), nodes_wo_self).unwrap();
//!    handles.push(thread::spawn(move || {
//!       // Take turns connecting to everyone else
//!       for j in 0..i {
//!          // Accept a connection
//!          let errors = local_node.listen();
//!       }
//!       // Now its your turn
//!       let errors = local_node.connect_all();
//!       println!("{:?}: Connected.", &local_node.address());
//!       // Wait for everyone to connect before beginning the protocol
//!       if i == 1 {
//!          thread::sleep(Duration::from_millis(10000));
//!          let errors = local_node.initiate(&shared_nonce.clone());
//!
//!       }
//!
//!       println!("{:?}: Waiting for consensus...", &local_node.address());
//!       // Process messages
//!        let consensus_or_timeout = local_node.wait_for_consensus(TICK_RATE, TIMEOUT, MAX_MISSING_LISTS);
//!       if let Some(consensus) = &consensus_or_timeout {
//!          println!("{:?}: CONSENSUS: {:?}", &local_node.address(), consensus);
//!
//!       };
//!       return consensus_or_timeout;
//!
//!    }));
//!
//! }
//!
//!   let mut results = Vec::<Option<Consensus>>::new();
//!   for handle in handles {
//!      results.push(handle.join().unwrap());
//!   }
//!
//!   assert_ne!(results[0], None);
//!   for number in &results {
//!      assert_eq!(number, &results[0]);
//!   }
//!   assert_eq!(results.len(), usize::from(NUM_OF_NODES));
//! ```
//!
//! In an actual usage scenario, nodes should reside on separate machines and not just separate threads.
//!
//! # How it Works
//!
//! The consensus mechanism is fairly simple. After a request from the client (not in the scope of this crate),
//! each node broadcasts their random number choice ("Block")
//! to all other nodes, then creates a List of the Blocks they receive: one for each node in their keyring,
//! and sign and broadcast that too. Once enough identical lists are collected, each node broadcasts their reveal key
//! corresponding to that consensus. Once all the reveal keys are collected, the decrypted arrays are summed by element
//! mod 2^8 = 256. The consensus is then signed by each node, and relayed to the client. If all but one node attempts
//! to manipulate the consensus, the "randomness" from that node's block is enough on its own to ensure the "randomness"
//! of the consensus. The more signatures on the same consensus, the more confident the client can be that it is indeed random.
//! One consequence of this design is that the nodes themselves must be trusted or chosen by random...
//!
//! The protocol is asynchronous. If a node goes offline, other nodes can relay its Blocks and Lists by responding
//! to RequestBlock or RequestList messages. However, this functionality is not implemented here yet.
//!
//! # Motivation
//!
//! Anonymous overlay networks like Tor or i2p permit clients to choose their own onion route. The client can only be
//! deanonymised if all of these nodes are malicious and coinciding. This works well for clearnet resources, but if the
//! server also wishes to remain anonymous, then they must choose their own route to be reachable from. For Tor onion sites,
//! this is 6 nodes total. If there was a trusted source of entropy (randomness), then both the client and server could use the
//! same 3 nodes, with the same chance of being deanonymised. Previous work, like the [TorPath protocol](https://dedis.cs.yale.edu/dissent/papers/hotpets14-torpath.pdf),
//! require zero-knowledge proofs with poor performance and implementation.
//!
//! # Maturity
//!
//! This crate is a personal, experimental project and is not yet stable. This is my first crate. Use at your own risk.
//!
//! # Errors
//!
//! Due to the natural volatility of network programming, this library was given a robust error system.
//! Their types are outlined below. Note that `wait_for_consensus()` currently hides most errors.
//!
//! `Connect`: An encrypted connection could not be created. \
//! `Start`: A local node could not be started (likely an OS error). \
//! `Packet`: A packet could not be en/decrypted, (de)serialized, or sent/received. \
//! `Broadcast`: There was an error that prevented a full broadcast. There may be multiple of these when calling
//! `broadcast()`, and printing all of them may be too verbose. \
//! `Reveal`: A reveal key either could not be broadcasted or could not be used to reveal a block. \
//!
//! Errors include a string description and may be nested.
//!
//! # Glossary
//!
//! Several new terms were created to describe unique concepts.
//!
//! - **Client**: A party not involved in the protocol who requests a random number from a group of nodes. The node then broadcasts an `Initiate` message
//! to start the consensus process.
//! - **Message**: A unit of communication for the protocol. See [`Message`].
//! - **Number**: Random bytes or entropy that are returned to the client.
//! - **Node**: An instance of the protocol whos identity (public/signing) key is partially trusted by the client.
//! - **Ring**: A group of nodes who are typically involved in the same consensuses.
//! - **Local Node**: The locally running node instance. See [`NodeLocal`].
//! - **Offline/Connected Node**: An object that stores information about other nodes. See [`NodeDown`] and [`NodeUp`].
//! - **[`Block`]**
//! - **[`List`]**
//! - **Consensus**: A number signed by one or more nodes. See [`Consensus`].
//! - **Shared Nonce**: Indicates which consensus a block or list belongs to. See [`SharedNonce`].
//!
//! # Future Improvements:
//!
//! **Functionality**
//! - [ ] Implement the logic for `RequestBlock`, `RequestList`, and `RequestReveal` message types to fully enable asynchronous usage
//! - [ ] Add a `Consensus` and `RequestConsensus` message type to allow a single node to relay it to a client
//! - [ ] Implement STD traits on important types
//! - [ ] Implement `Serialize` and `Deserialize` on `NodeLocal` to support saving state to disk
//! - [ ] Manually implement `Debug`/`Display` on `VerifyingKey` to show public (identity) keys in hex formatting
//!
//! **Safety/Security/Correctness/Reliability**
//! - [ ] Handle disconnects gracefully
//! - [ ] **Write better tests**
//! - [ ] Add lints
//! - [ ] Add safeguards to iterations over indexes, which will panic if length is zero
//! - [ ] Support disk caching of shared nonces to make sure they are not repeated
//!
//! **Performance**
//! - [ ] Reduce the number of search algorithms (perhaps using presorted vectors and binary search?)
//! - [ ] Introduce more zero-copy operations
//! - [ ] Use more stack allocation rather than heap allocation
//!
//! **Clarity**
//! - [ ] Make `[u8; 32]` a type alias with a more descriptive name than `Number`
//! - [ ] Add more comments
//! - [ ] Replace some for loops with iterators for consistency
//! - [ ] Remove some `unwrap()`s (not idiomatic Rust)
//! - [ ] Replace repetitive code in several `to_bytes()` methods to use iterators
//! - [ ] Make sure API follows Rust guidelines
//! - [ ] Provide documentation examples for every important item
//!
//! # Contributing
//!
//! Issues and PRs are welcome, but my responses may not always be timely. Help is needed on the tasks above and
//! I left some FIXMEs/TODOs/FUTUREs where I couldn't make up my own mind. Some code is dubious and needs feedback.
//!
//! # Contact
//!
//! My contact info, up to date, is available on my GitHub profile: [github.com/devnetsec](https://github.com/devnetsec)
//!
//! # Copying
//!
//! This work is dual‐licensed under Apache 2.0 and MIT terms.


pub mod node;
pub mod message;
pub mod error;
pub mod consts;

extern crate ed25519_dalek;
extern crate serde;
extern crate aes_gcm;
extern crate rand;
extern crate x25519_dalek;

pub use crate::node::{Node, NodeLocal, NodeDown, NodeUp};
pub use crate::error::{Err, ErrType};
pub use crate::message::{Message, Block, List, Consensus, Status, SharedNonce};

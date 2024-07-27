// Threads
use std::thread;
use std::time::Duration;

// Networking
use std::net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs};
use std::io::prelude::*;

// Encryption
use ed25519_dalek::{SigningKey, Signature, VerifyingKey, Signer, Verifier};
use x25519_dalek::{EphemeralSecret, PublicKey};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key
};

// Error handling
use crate::{ERR, error::{Err, ErrType, ErrSrc}};
use crate::error;

use std::collections::HashMap;
use std::default::Default;

use crate::message::{SharedNonce, Message, Block, List, Consensus, Status};
use crate::consts::*;

use rand::random;
use rand::prelude::SliceRandom;

/// Common getters for `NodeDown` and `NodeUp`, so they can be processed in the same collection.
/// # Example
/// ```
/// use rand_num_consensus::{Node, NodeDown, NodeLocal};
/// use std::time::Duration;
/// use ed25519_dalek::SigningKey;
/// use std::thread;
///
/// // Other offline nodes from this node's perspective
/// let offline_nodes = [NodeDown::default(), NodeDown::default(), NodeDown::default()];
///
/// // This node from another node's perspective
/// let my_signing_key = SigningKey::from(rand::random::<[u8; 32]>());
/// let mut me = NodeDown::default();
/// me.identity_key = my_signing_key.verifying_key();
///
/// // Another node from this node's perspective
/// let their_signing_key = SigningKey::from(rand::random::<[u8; 32]>());
/// let mut them = NodeDown::default();
/// them.identity_key = their_signing_key.verifying_key();
///
/// // Another node from their own perspective
/// let mut node_to_connect_to = NodeLocal::new(their_signing_key, &String::from("127.0.0.1:50000"), vec![me]).expect("Socket coud not be opened");
/// let handle = thread::spawn(move || {
///    node_to_connect_to.listen();
/// });
/// // Give the other thread some time to start up
/// thread::sleep(Duration::from_millis(100));
/// them.connect(&my_signing_key);
///
/// let mut useful_node_info = Vec::<String>::new();
///
/// let mut all_nodes = Vec::<&(dyn Node)>::new();
/// all_nodes.extend(offline_nodes.iter().map(|node| node as &(dyn Node)));
/// all_nodes.push(&them as &(dyn Node));
/// for (i, node) in all_nodes.iter().enumerate() {
///    let format_addr = format!("Node {:?}'s address: {:?}", (i+1), node.address());
///    useful_node_info.push(format_addr);
/// }
///
/// handle.join().unwrap();
///
/// assert_eq!(useful_node_info, vec!["Node 1's address: 127.0.0.1:50000",
/// "Node 2's address: 127.0.0.1:50000",
/// "Node 3's address: 127.0.0.1:50000",
/// "Node 4's address: 127.0.0.1:50000"]);
/// ```
pub trait Node {
   fn identity_key(&self) -> &VerifyingKey;
   fn address(&self) -> &SocketAddr;
   fn address_mut(&mut self) -> &mut SocketAddr;
   fn revealed_blocks(&self) -> &HashMap<SharedNonce, [u8; 32]>;
   fn revealed_blocks_mut(&mut self) -> &mut HashMap<SharedNonce, [u8; 32]>;
   fn blocks(&self) -> &Vec<Block>;
   fn blocks_mut(&mut self) -> &mut Vec<Block>;
   fn lists(&self) -> &Vec<List>;
   fn lists_mut(&mut self) -> &mut Vec<List>;
}

// FIXME: Derive Serialize and Deserialize to allow file storage
//#[derive(Serialize, Deserialize)]
/// Local node instance that automatically handles connections and most of the protocol.
/// # Example
/// See [`crate`].
pub struct NodeLocal {
   identity_key: VerifyingKey,
   signing_key: SigningKey,
   address: SocketAddr,
   offline_nodes: Vec<NodeDown>,
   connected_nodes: Vec<NodeUp>,

   listener: TcpListener,
   // A list of blocks created by this node and their associated secret key
   reveal_keys: HashMap<SharedNonce, Key<Aes256Gcm>>,
   blocks: Vec<Block>,

   lists: Vec<List>,
   lists_to_reveal: Vec<List>,
}

impl NodeLocal {
   /// Creates a new `NodeLocal`.
   /// # Errors
   /// Will return an `Err::Connect` if a socket could not be configured,
   /// if two offline nodes (`NodeDown`s) share the same identity key or if none were provided.
   pub fn new(signing_key: SigningKey, address: &impl ToSocketAddrs, offline_nodes: Vec<NodeDown>) -> Result<Self, Err> {
      if offline_nodes.is_empty() {
         return Err(ERR!("No remote node information provided", Start));
      }
      let listener = TcpListener::bind(address)
         .map_err(|err| ERR!("Could not start TCP listener", Start, err))?;

      listener.set_nonblocking(false)
         .map_err(|err| ERR!("Could not set TCP listener to blocking", Start, err))?;

      let identity_key = signing_key.verifying_key();

      // Check if each node has a unique identity key
      let mut unique_identity_keys = HashMap::<&VerifyingKey, usize>::new();
      offline_nodes
         .iter()
         .map(|node| node.identity_key())
         .for_each(|identity_key| {
            let matches = unique_identity_keys.entry(identity_key).or_insert_with(|| 0usize);
            *matches += 1;
         });
      if let Some(_) = unique_identity_keys
         .iter()
         .map(|datum| datum.1)
         .find(|&frequency| *frequency > 1usize)
      {
         return Err(ERR!("Not every offline node has a unique identity key", Start));
      }

      return Ok(NodeLocal {
         identity_key,
         signing_key,
         address: address.to_socket_addrs().unwrap().next().unwrap(),
         offline_nodes,
         connected_nodes: Vec::<NodeUp>::new(),
         listener,
         reveal_keys: HashMap::<SharedNonce, Key<Aes256Gcm>>::new(),
         blocks: Vec::<Block>::new(),
         lists: Vec::<List>::new(),
         lists_to_reveal: Vec::<List>::new(),
      });
   }
   /// Block while waiting for one incoming connection to this node.
   /// # Errors
   /// The error vector will contain `Err::Connect`s
   /// if there were sockets that could not be configured, a connection request packet was malformed, if the connection was dropped
   /// while responding, if the connection could not be authenticated, or if the connection does not originate from a known node.
   pub fn listen(&mut self) -> Vec<Err> {
      let mut errors = Vec::<Err>::new();

      if let Ok((stream, _peer_addr)) = self.listener.accept() {
         match self.accept_connection(stream) {
            Err(err) => {
               errors.push(err);
            }
            Ok(new_connection) => {
               self.connected_nodes.push(new_connection);
            }

         };

      }
      else { errors.push(ERR!("TCP listener could not accept connection", Connect)); }

      return errors;

   }

   /// Reads messages from each connected node and processes them accordingly.
   /// Returns the next consensus reached, or None on timeout.
   ///
   /// # Parameters
   /// `tick_rate`: the number of milliseconds between each state update. \
   /// `timeout`: the max number of milliseconds to block on this thread. \
   /// `max_missing_lists`: the largest number of lists to that may be missing from a consensus. **Suggested value**: 0.
   // TODO: Determine if this feature should be removed outright
   /// By performing a DOS attack, an adversary could bring non-malicious nodes offline, potentially giving malicious ones complete control of the consensus.
   /// Additionally, clients might not accept consensuses with missing signatures like this. To increase reliable, instead decrease the number of nodes in the ring.
   pub fn wait_for_consensus(&mut self, tick_rate: u64, timeout: u64, max_missing_lists: usize) -> Option<Consensus> {
      let mut counter = 0u64;
      loop {

         for i in 0..self.connected_nodes.len() {

            let (messages, _errors) = self.connected_nodes[i].recv_messages();

            for message in messages {
               match message {
                  Message::Initiate(shared_nonce) => {
                     let (new_block, new_key) = Block::new(&shared_nonce, &self.signing_key);
                     if let None = self.reveal_keys.get(&shared_nonce) {
                        self.reveal_keys.insert(shared_nonce, new_key);
                     }
                     // .clone() here to avoid binding then unwrapping this enum
                     // hide errors
                     self.broadcast(&Message::Block(new_block.clone()));

                     self.blocks.push(new_block);
                  }
                  Message::Block(block) => {

                     // create and broadcast a block if the local node does not already have one with the same SharedNonce
                     if let None = self.blocks
                        .iter()
                        .find(|&my_block| my_block.shared_nonce() == block.shared_nonce()) {
                        let (new_block, new_key) = Block::new(&block.shared_nonce(), &self.signing_key);
                        // hide errors here that may be too verbose
                        self.broadcast(&Message::Block(new_block.clone()));
                        self.reveal_keys.entry(block.shared_nonce().clone()).or_insert(new_key);
                        self.blocks.push(new_block);
                     }

                     let all_nodes_wo_self_mut = Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes);
                     if let Some(_) = self.blocks.iter().find(|&my_block| my_block.shared_nonce() == block.shared_nonce()) {
                        block.add(all_nodes_wo_self_mut, &self.identity_key);
                     }

                  }

                  Message::List(list) => {
                     let all_nodes_wo_self_mut = Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes);
                     list.add(all_nodes_wo_self_mut, &self.identity_key);
                  }

                  Message::Reveal(identity_key, shared_nonce, reveal_key) => {
                     // Update lists_to_reveal
                     self.broadcast_reveal(max_missing_lists);
                     // FIXME: handle errors
                     if let Some(list) = self.lists_to_reveal
                        .iter()
                        .find(|list| list.shared_nonce() == &shared_nonce)
                     {
                        if let Some(block) = list
                           .blocks()
                           .iter()
                           .find(|block| block.identity_key() == &identity_key)
                        {
                           if let Ok(revealed_number) = block.reveal(&reveal_key) {
                              if let Some(node) = Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes)
                                 .into_iter()
                                 .find(|node| node.identity_key().as_bytes() == &identity_key)
                              {
                                 node.revealed_blocks_mut().entry(shared_nonce).or_insert_with(|| revealed_number);

                                 let consensus_shared_nonce = list.shared_nonce().clone();
                                 let try_reveal = self.try_reveal();
                                 if let Some(revealed_number) = try_reveal {
                                    return Some(Consensus::new(&self.signing_key, revealed_number, consensus_shared_nonce));
                                 }

                              }


                           }
                           else {
                              ();
                           }
                        }
                     }

                  }
                  // FUTURE: handle RequestBlock, RequestList, and RequestReveal messages

               }
            }

         }

         thread::sleep(Duration::from_millis(tick_rate + 1));
         counter += 1;

         if counter >= (timeout / tick_rate) {
            return None;
         }

         // Start list phase
         if counter >= TICKS_BEFORE_START_LIST {
            let my_identity_key = self.identity_key.clone();
            // FUTURE: This could be made more efficient
            for i in 0..self.blocks.len() {
               if let Ok(mut new_list) = List::new(Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes), my_identity_key, &self.blocks[i].shared_nonce(), self.blocks[i].clone()) {
                  new_list.sign(&self.signing_key);
                  self.broadcast(&Message::List(new_list.clone()));
                  self.lists.push(new_list);
               }

            }

         }

         if counter >= TICKS_BEFORE_START_REVEAL {
            self.broadcast_reveal(max_missing_lists);
         }

      }

   }

   fn all_nodes_wo_self_mut<'a>(connected_nodes: &'a mut Vec<NodeUp>, offline_nodes: &'a mut Vec<NodeDown>) -> Vec<&'a mut (dyn Node)> {
      let mut all_nodes = Vec::<&mut (dyn Node)>::new();
      all_nodes.extend(offline_nodes.iter_mut().map(|x| x as &mut (dyn Node)));
      all_nodes.extend(connected_nodes.iter_mut().map(|x| x as &mut (dyn Node)));
      return all_nodes;
   }

   fn all_nodes_wo_self<'a>(connected_nodes: &'a Vec<NodeUp>, offline_nodes: &'a Vec<NodeDown>) -> Vec<&'a (dyn Node)> {
      let mut all_nodes = Vec::<&(dyn Node)>::new();
      all_nodes.extend(offline_nodes.iter().map(|x| x as & (dyn Node)));
      all_nodes.extend(connected_nodes.iter().map(|x| x as & (dyn Node)));
      return all_nodes;
   }

   fn broadcast(&mut self, message: &Message) -> Vec<Err> {
      let mut errors = Vec::<Err>::new();
      for node in &mut self.connected_nodes {
         if let Err(err) = node.send_message(message) {
            errors.push(ERR!("", Broadcast, err));
         }
      }
      return errors;
   }

   /// Attempt to connect to every offline node. Returns an error for every connection failed, which may be too verbose.
   pub fn connect_all(&mut self) -> Vec<Err> {
      let mut errors = Vec::<Err>::new();
      let mut i = 0usize;
      while !self.offline_nodes.is_empty() && i < self.offline_nodes.len() {
         match self.offline_nodes[i].connect(&self.signing_key) {
            Err(err) => {
               errors.push(err);
               i += 1;
            }
            Ok(connection) => {
               self.connected_nodes.push(connection);
               self.offline_nodes.swap_remove(i);
            }
         }
      }

      return errors;
   }


   /// Create a new authentication packet for a Diffie-Hellman exchange by signing an ephemeral key.
   pub fn new_auth_packet(signing_key: &SigningKey, secret_key: &EphemeralSecret) -> [u8; 128] {
      let mut packet: [u8; 128] = [0u8; 128];

      let public_key = PublicKey::from(secret_key);

      signing_key.verifying_key().to_bytes()
         .iter()
         .enumerate()
         .for_each(|b| packet[b.0] = *b.1);
      public_key.to_bytes()
         .iter()
         .enumerate()
         .for_each(|b| packet[b.0 + 32usize] = *b.1);
      signing_key.sign(&packet[32..64]).to_bytes()
         .iter()
         .enumerate()
         .for_each(|b| packet[b.0 + 64usize] = *b.1);

      return packet;
   }

   fn try_reveal(&mut self) -> Option<[u8; 32]> {
      // Construct a new vector even if no list can be revealed for simplicity
      let mut revealed_list = Vec::<[u8; 32]>::new();
      'lists: for list in &self.lists_to_reveal {
         for block in list.blocks() {
            if let Some(node) = Self::all_nodes_wo_self(&self.connected_nodes, &self.offline_nodes)
               .iter_mut()
               .find(|node| node.identity_key().as_bytes() == block.identity_key())
            {
               if let Some(revealed_block) = node.revealed_blocks().get(list.shared_nonce()) {
                  revealed_list.push(revealed_block.clone());

               }
               else {
                  revealed_list.clear();
                  continue 'lists;
               }
            }

         }


         if let Some(reveal_key) = self.reveal_keys.get(list.shared_nonce()) {
            if let Some(block) = self.blocks
               .iter()
               .find(|block| block.shared_nonce() == list.shared_nonce())
            {
               // Should never panic unless something is wrong with this node anyway
               revealed_list.push(block.reveal(&reveal_key.to_vec()).unwrap());
               self.reveal_keys.remove(list.shared_nonce());
            }

         }
         // FIXME: error here instead?
         else {
            return None;
         }

         for node in Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes) {
            node.revealed_blocks_mut().remove(list.shared_nonce());
         }

         return Some(revealed_list
            .iter()
            .fold([0u32; 32], |mut acc, num| { for (i, x) in num.iter().enumerate() {
               acc[i] += <u32>::from(*x);
            } acc })
            .iter()
            .map(|x| <u8>::try_from((x + 256u32) % 256u32).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap());

      }

      return None;
   }

   fn broadcast_reveal(&mut self, max_missing_lists: usize) -> Result<(), Err> {
      let remove_lists = self.find_lists_to_reveal(max_missing_lists);
      for list in remove_lists {
         if let Some(key) = self.reveal_keys.get(list.shared_nonce()) {
            // Hide errors, may be too verbose
            self.broadcast(&Message::Reveal(self.identity_key.to_bytes(), list.shared_nonce().clone(), key.to_vec()));
         }
         else {
            return Err(ERR!("No block key found on local node", Reveal));
         }
      }

      return Ok(());
   }

   fn find_lists_to_reveal(&mut self, max_missing_nodes: usize) -> Vec<List> {

      let mut unique_lists = HashMap::<&List, usize>::new();
      let all_nodes = Self::all_nodes_wo_self(&self.connected_nodes, &self.offline_nodes);
      all_nodes
         .iter()
         .map(|node| node.lists().iter())
         .flatten()
         .for_each(|list| {
            let matches = unique_lists.entry(list).or_insert_with(|| 0usize);
            *matches += 1;
         });
      self.lists
         .iter()
         .for_each(|list| {
            let matches = unique_lists.entry(list).or_insert_with(|| 0usize);
            *matches += 1;
         });

      let remove_lists: Vec<List> = unique_lists
         .into_iter()
         .filter(|matches| matches.1 >= (Self::all_nodes_wo_self(&self.connected_nodes, &self.offline_nodes).len() - max_missing_nodes))
         .map(|list| list.0.clone() )
         .collect();

      // TODO: Remove .cloned() and use for loops instead
      for node in Self::all_nodes_wo_self_mut(&mut self.connected_nodes, &mut self.offline_nodes) {
         *node.lists_mut() = node.lists_mut()
            .iter()
            .cloned()
            .filter(|list| !remove_lists.contains(&list))
            .collect::<Vec<List>>();
      }
      self.lists = self.lists
         .iter()
         .cloned()
         .filter(|list| !remove_lists.contains(&list))
         .collect::<Vec<List>>();
      self.lists_to_reveal.append(&mut remove_lists.clone());
      return remove_lists;

   }

   fn accept_connection(&mut self, mut stream: TcpStream /* SocketAddr */) -> Result<NodeUp, Err> {

      stream.set_nonblocking(false)
         .map_err(|err| ERR!("Could not set TCP stream to blocking. ", Connect, err))?;
      stream.set_read_timeout(Some(TCP_STREAM_TIMEOUT))
         .map_err(|err| ERR!("Could not set read timeout on socket", Connect, err))?;
      stream.set_write_timeout(Some(TCP_STREAM_TIMEOUT))
         .map_err(|err| ERR!("Could not set write timeout on socket", Connect, err))?;
      // Slightly larger buffer to be able to detect invalid packet sizes
      let mut buffer: [u8; 130] = [0u8; 130];

      let packet_length = stream.read(&mut buffer)
         .map_err(|err| ERR!("Could not read from TCP stream", Connect, err))?;

      if packet_length != 128 {
         return Err(ERR!("Received a packet of invalid length", Connect, packet_length));
      }

      let secret_key = EphemeralSecret::random();
      // Check if this node is in our keyring
      // (use index for .swap_remove())
      for i in 0..self.offline_nodes.len() {
         if self.offline_nodes[i].identity_key.as_bytes().as_slice() == &buffer[..32] {
            match self.offline_nodes[i].authenticate(buffer) {
               Err(_) => {
                  // hide errors
                  continue;
               }
               Ok(_) => {

                  stream.write(&NodeLocal::new_auth_packet(&self.signing_key, &secret_key))
                     .map_err(|err| ERR!("Could not write to TCP stream", Connect, err))?;

                  // Support wait_for_consensus()'s simple single threaded architecture
                  stream.set_nonblocking(true)
                     .map_err(|err| ERR!("Could not set TCP stream to nonblocking. ", Connect, err))?;

                  let shared_secret = secret_key.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&buffer[32..64]).unwrap())).to_bytes();

                  return Ok(NodeUp {
                     stream,
                     // Should never panic
                     session_key: Aes256Gcm::new_from_slice(&shared_secret).unwrap(),
                     node: self.offline_nodes.swap_remove(i),
                  })
               }
            }
         }
      }

      return Err(ERR!("Could not authenticate connection", Connect));
   }

   /// Broadcast a `Message::Initiate` to all connected nodes, starting the consensus process.
   pub fn initiate(&mut self, shared_nonce: &SharedNonce) -> Vec<Err> {
      let mut errors = Vec::<Err>::new();
      errors.extend(self.broadcast(&Message::Initiate(shared_nonce.clone())));
      let (new_block, new_key) = Block::new(&shared_nonce, &self.signing_key);
      // FIXME: or_insert_with() would be better here
      if let None = self.reveal_keys.get(shared_nonce) {
         self.reveal_keys.insert(shared_nonce.clone(), new_key);
         // .clone() to avoid binding then unwraping this enum
         self.blocks.push(new_block.clone());
         errors.extend(self.broadcast(&Message::Block(new_block)));
      }



      return errors;
   }

   /// Returns true if there are no more offline nodes.
   pub fn is_connected_to_all(&self) -> bool {
      return self.offline_nodes.is_empty();
   }

   pub fn address(&self) -> &SocketAddr { return &self.address; }

   /// Returns the lists that are waiting to be revealed (waiting for reveal keys to be received).
   pub fn lists_to_reveal(&self) -> &Vec<List> { return &self.lists_to_reveal }
}

#[derive(Clone)]
/// An offline remote node interface that can be used to store its state.
///
/// # Example
/// ```
/// use rand_num_consensus::consts;
/// use rand_num_consensus::{SharedNonce, Node, NodeDown, NodeUp, NodeLocal, Message, Status, Block};
/// use ed25519_dalek::SigningKey;
/// use x25519_dalek::{EphemeralSecret, PublicKey};
/// use aes_gcm::{Aes256Gcm, KeyInit};
/// use rand::random;
/// use std::net::{ToSocketAddrs, TcpListener};
/// use std::thread;
/// use std::time::Duration;
/// use std::io::prelude::*;
///
/// // Create a new identifier for this consensus
/// let shared_nonce: SharedNonce = rand::random::<[u8; 16]>();
///
/// // This node from another node's perspective
/// let mut me: NodeDown = Default::default();
/// let my_signing_key = SigningKey::from(random::<[u8; 32]>());
/// me.identity_key = my_signing_key.verifying_key();
/// me.address = "127.0.0.1:51000"
///    .to_socket_addrs()
///    .unwrap()
///    .next()
///    .unwrap();
///
/// // Another node from this node's perspective
/// let their_signing_key = SigningKey::from(rand::random::<[u8; 32]>());
/// let mut them = NodeDown::default();
/// them.identity_key = their_signing_key.verifying_key();
/// let their_address = "127.0.0.1:50000".to_socket_addrs()
///    .unwrap()
///    .next()
///    .unwrap();
///
/// let listener = TcpListener::bind(their_address).expect("Could not open socket!");
///
/// // Simulate a separate computer by spawing a new thread.
/// let handle = thread::spawn(move || {
///    let mut stream = listener.accept().expect("Could not accept connection!").0;
///
///    stream.set_nonblocking(false).unwrap();
///    stream.set_read_timeout(Some(consts::TCP_STREAM_TIMEOUT)).unwrap();
///    stream.set_write_timeout(Some(consts::TCP_STREAM_TIMEOUT)).unwrap();
///
///    let mut buffer = [0u8; 130];
///    stream.read(&mut buffer).unwrap();
///    if let Ok(_) = me.authenticate(buffer) {
///       /// Respond to the connection request.
///       let secret_key = EphemeralSecret::random();
///       stream.write(&NodeLocal::new_auth_packet(&their_signing_key, &secret_key)).unwrap();
///
///       // This node is now connected.
///       let mut me = NodeUp::new(me, stream, Aes256Gcm::new_from_slice(&secret_key.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&buffer[32..64]).unwrap())).to_bytes()).unwrap());
///       // Respond to a Message.
///       if let Message::Initiate(shared_nonce) = me.recv_messages().0[0] {
///          me.send_message(&Message::Block(Block::new(&shared_nonce, &their_signing_key).0));
///       }
///    }
///    else { panic!() }
///
/// });
///
/// // Connect to another node
/// let mut them = them.connect(&my_signing_key).expect("Failed to connect!");
///
/// // Send a Message
/// them.send_message(&Message::Initiate(shared_nonce));
/// thread::sleep(Duration::from_millis(100));
/// let (messages, _errors) = them.recv_messages();
///
/// assert_eq!(messages.len(), 1usize);
/// if let Message::Block(block) = &messages[0] {
///    assert_eq!(block.verify(&vec![&mut them as &mut dyn Node], &my_signing_key.verifying_key()), Status::Peer)
/// }
/// else {
///    panic!();
/// }
///
/// handle.join().unwrap();
/// ```
pub struct NodeDown {
   pub identity_key: VerifyingKey,
   pub address: SocketAddr,
   revealed_blocks: HashMap<SharedNonce, [u8; 32]>,
   blocks: Vec<Block>,
   lists: Vec<List>,
}


impl NodeDown {
   /// Attempt to establish an authenticated, encrypted connection to this node using the signing key of a local node.
   /// Proprogates several socket/network errors. The
   /// resulting TCP stream is set to non-blocking to support the current single-threaded
   /// architecture.
   pub fn connect(&self, signing_key: &SigningKey) -> Result<NodeUp, Err> {
      let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))
         .map_err(|err| ERR!("Could not open TCP connection (node may not be online)", Connect, err))?;

      stream.set_read_timeout(Some(TCP_STREAM_TIMEOUT))
         .map_err(|err| ERR!("Could not set read timeout on socket", Connect, err))?;
      stream.set_write_timeout(Some(TCP_STREAM_TIMEOUT))
         .map_err(|err| ERR!("Could not set write timeout on socket", Connect, err))?;

      let secret_key = EphemeralSecret::random();

      // set the TCP stream to blocking to wait for a response on this socket
      stream.set_nonblocking(false)
         .map_err(|err| ERR!("Could not set TCP stream to blocking. ", Connect, err))?;

      let _ = stream.write(&NodeLocal::new_auth_packet(signing_key, &secret_key))
         .map_err(|err| ERR!("Could not write to TCP stream", Connect, err))?;

      let mut buffer: [u8; 130] = [0u8; 130];

      let packet_length = stream.read(&mut buffer)
         .map_err(|err| ERR!("Could not read from TCP stream (remote node may have closed connection)", Connect, err))?;

      if packet_length != 128 {
         return Err(ERR!("Received a packet of invalid length", Connect, packet_length));
      }

      // Support wait_for_consensus()'s simple single threaded architecture
      stream.set_nonblocking(true)
         .map_err(|err| ERR!("Could not set TCP stream to unblocking. ", Connect, err))?;

      let shared_secret = secret_key.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&buffer[32..64]).unwrap())).to_bytes();

      match self.authenticate(buffer) {
         Err(err) => return Err(ERR!(err)),
         Ok(_) => return Ok(NodeUp {
            stream,
            session_key: Aes256Gcm::new_from_slice(&shared_secret).unwrap(),
            node: self.clone(),
         }),
      }
   }

   pub fn authenticate(&self, buffer: [u8; 130]) -> Result<(), Err> {
      if self.identity_key.as_bytes().as_slice() == &buffer[0..32] {
         self.identity_key.verify(&buffer[32..64], &Signature::from_slice(&buffer[64..128]).unwrap())
            .map_err(|err| ERR!("Could not verify session key", Connect, err))?;
      }
      else {
         return Err(ERR!("Mismatched identity keys", Connect));
      }

      return Ok(());
   }
}

impl Node for NodeDown {
   // Getters
   fn identity_key(&self) -> &VerifyingKey { return &self.identity_key; }
   fn address(&self) -> &SocketAddr { return &self.address; }
   fn address_mut(&mut self) -> &mut SocketAddr { return &mut self.address; }
   fn revealed_blocks(&self) -> &HashMap<SharedNonce, [u8; 32]> { return &self.revealed_blocks }
   fn revealed_blocks_mut(&mut self) -> &mut HashMap<SharedNonce, [u8; 32]> { return &mut self.revealed_blocks }
   fn blocks(&self) -> &Vec<Block> { return &self.blocks; }
   fn blocks_mut(&mut self) -> &mut Vec<Block> { return &mut self.blocks; }
   fn lists(&self) -> &Vec<List> { return &self.lists; }
   fn lists_mut(&mut self) -> &mut Vec<List> { return &mut self.lists; }
}

impl Default for NodeDown {
   // Unuseful default instantiation for testing
   fn default() -> Self {
      return NodeDown {
         identity_key: SigningKey::from(random::<[u8; 32]>()).verifying_key(),
         // Should never panic
         address: "127.0.0.1:50000".to_socket_addrs().unwrap().next().unwrap(),
         revealed_blocks: HashMap::<SharedNonce, [u8; 32]>::new(),
         blocks: Vec::<Block>::new(),
         lists: Vec::<List>::new(),
      }
   }
}

/// A connected remote node interface that can be used to send and receive `Message`s.
/// # Example
///
/// See [`NodeDown`].
pub struct NodeUp {
   session_key: Aes256Gcm,
   stream: TcpStream,
   node: NodeDown,
}


impl NodeUp {
   /// Pass a manually created connection and set a node to online.
   pub fn new(node: NodeDown, stream: TcpStream, session_key: Aes256Gcm) -> Self {
      return NodeUp {
         session_key,
         stream,
         node,
      };
   }
   /// Attempts to serialize, encrypt, and send a `Message` to this node.
   /// # Errors
   /// Returns an `Err::Packet` if the TCP stream could not be written to, indicating that the node may have disconnected.
   pub fn send_message(&mut self, message: &Message) -> Result<(), Err> {

      let mut packet = Vec::<u8>::new();

      let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
      // Should never panic
      let serialized = bincode::serialize(&message).unwrap();
      let ciphertext = self.session_key.encrypt(&nonce, &serialized[..]).unwrap();
      // Add a 16-bit packet length header, to accomodate lists of up to ~364 blocks
      let packet_length = 12u16 + 2u16 + u16::try_from(ciphertext.len()).unwrap();
      packet.extend_from_slice(&packet_length.to_be_bytes()[..]);

      packet.extend_from_slice(&nonce);
      packet.extend_from_slice(&ciphertext);

      self.stream.write(&packet)
         .map_err(|err| ERR!(format!("Could not write to TCP stream ({:?} may have disconnected)", self.node.address), Packet/* Send*/, err))?;

      return Ok(());
   }

   /// Attempts to read, decrypt, and deserialize any number of messages received from this node.
   /// Will generally return errors if the received data is corrupt or malformed. **Does not block.**
   pub fn recv_messages(&mut self) -> (Vec<Message>, Vec<Err>) {
      let mut messages = Vec::<Message>::new();
      let mut errors = Vec::<Err>::new();

      let mut buffer = [0u8; 65536];
      let mut length_read = 0usize;
      match self.stream.read(&mut buffer) {
         Err(_err) => (), //errors.push(ERR!("Could not read from TCP stream", Recv, err)), //TODO: too verbose, replace with if let
         Ok(_length_read) => length_read = _length_read,
      }

      let mut next_index = 0usize;
      while length_read > next_index {
         // FIXME: Don't initialize Vec for every loop iteration

         // Read the first two bytes as a u16
         // Should never panic
         let packet_length = usize::from(u16::from_be_bytes(<[u8; 2]>::try_from(&buffer[next_index..next_index + 2]).unwrap()));

         // Gracefully handle invalid packet header
         if packet_length > length_read {
            errors.push(ERR!("Invalid packet length", Packet));
            break;
         }

         let packet = Vec::from(&buffer[next_index..(next_index + packet_length)]);
         next_index += packet_length;

         // Should never panic
         // Skip first two bytes (length header)
         if packet.len() >= (12 + 2) {
            let nonce = <[u8; 12]>::try_from(&packet[2..14]).unwrap();

            let mut plaintext = Vec::<u8>::new();
            match self.session_key.decrypt(&nonce.into(), &packet[14..]) {
               Err(_) => errors.push(ERR!("Could not decrypt packet", Packet)),
               Ok(_plaintext) => plaintext = _plaintext,
            }

            match bincode::deserialize::<Message>(&plaintext) {
               Err(err) => errors.push(ERR!("Could not deserialize packet", Packet, err)),
               Ok(deserialized) => messages.push(deserialized),
            }

         }
         else {
            errors.push(ERR!("Invalid packet length", Packet));
         }

      }

      return (messages, errors);

   }

   // FUTURE: Send a Disconnect notification to this peer node
   /// Close the connection and change the node to offline. **Not currently tested or useful.**
   pub fn disconnect(self) -> NodeDown { return self.node }

}

impl Node for NodeUp {
   // Getters
   fn identity_key(&self) -> &VerifyingKey { return &self.node.identity_key; }
   fn address(&self) -> &SocketAddr { return &self.node.address; }
   fn address_mut(&mut self) -> &mut SocketAddr { return &mut self.node.address; }
   fn revealed_blocks(&self) -> &HashMap<SharedNonce, [u8; 32]> { return &self.node.revealed_blocks }
   fn revealed_blocks_mut(&mut self) -> &mut HashMap<SharedNonce, [u8; 32]> { return &mut self.node.revealed_blocks }
   fn blocks(&self) -> &Vec<Block> { return &self.node.blocks; }
   fn blocks_mut(&mut self) -> &mut Vec<Block> { return &mut self.node.blocks; }
   fn lists(&self) -> &Vec<List> { return &self.node.lists; }
   fn lists_mut(&mut self) -> &mut Vec<List> { return &mut self.node.lists; }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticate() {
       let signing_key = SigningKey::from(random::<[u8; 32]>());
       let auth_packet = NodeLocal::new_auth_packet(&signing_key, &EphemeralSecret::random());
       let mut node = NodeDown::default();
       node.identity_key = signing_key.verifying_key();
       let mut auth_packet_two_more_bytes = [0u8; 130];
       auth_packet
         .iter()
         .enumerate()
         .for_each(|(i, byte)| auth_packet_two_more_bytes[i] = *byte);
       assert_eq!(node.authenticate(auth_packet_two_more_bytes), Ok(()));

    }
    #[test]
    // TODO: Split into smaller test functions
    // Also tests List::new(), List::sign(), and List::add()
    fn test_find_lists_to_reveal_and_try_reveal() {

      for i in 1..10 {
         let shared_nonce = random::<[u8; 16]>();

         let local_node_signing_key = SigningKey::from(random::<[u8; 32]>());
         let (local_node_block, local_node_reveal_key) = Block::new(&shared_nonce, &local_node_signing_key);

         let mut nodes = Vec::<NodeDown>::new();
         let mut signing_keys = Vec::<SigningKey>::new();


         let mut local_node = NodeDown {
            identity_key: local_node_signing_key.verifying_key(),
            ..Default::default()
         };
         local_node.blocks_mut().push(local_node_block.clone());

         for _ in 0..i {
            let signing_key = SigningKey::from(random::<[u8; 32]>());
            let (block, reveal_key) = Block::new(&shared_nonce, &signing_key);
            let blocks = vec![block.clone()];
            let mut new_node = NodeDown {
               identity_key: signing_key.verifying_key(),
               blocks,
               ..Default::default()
            };
            new_node.revealed_blocks_mut().insert(shared_nonce.clone(), block.reveal(&reveal_key.to_vec()).unwrap());
            nodes.push(new_node);
            signing_keys.push(signing_key);

         }

         let mut lists = Vec::<List>::new();
         for i in 0..nodes.len() {
            let mut nodes_wo_self = nodes.clone();
            nodes_wo_self.remove(i);
            nodes_wo_self.shuffle(&mut OsRng);

            let identity_key = nodes[i].identity_key().clone();
            let my_block = nodes[i].blocks()[0].clone();
            let mut local_node_2 = local_node.clone();
            let mut all_nodes: Vec<&mut dyn Node> = nodes_wo_self.iter_mut().map(|node| node as &mut dyn Node).collect();
            all_nodes.push(&mut local_node_2 as &mut dyn Node);
            let mut new_list = List::new(all_nodes, identity_key, &shared_nonce, my_block).unwrap();
            // Sign using the parallel array
            new_list.sign(&signing_keys[i]);
            lists.push(new_list);
         }

         let mut local_node = NodeLocal::new(local_node_signing_key, &String::from("127.0.0.1:50000"), nodes.clone()).unwrap();
         let local_node_list = List::new(nodes.iter_mut().map(|node| node as &mut dyn Node).collect(), local_node.identity_key.clone(), &shared_nonce.clone(), local_node_block.clone()).unwrap();
         local_node.lists.push(local_node_list.clone());
         local_node.reveal_keys.insert(shared_nonce.clone(), local_node_reveal_key);
         for list in lists {
            assert_eq!(list.add(local_node.offline_nodes.iter_mut().map(|node| node as &mut dyn Node).collect(), &local_node.identity_key), Status::Peer);
         }
         let lists_found = local_node.find_lists_to_reveal(0usize);

         assert_eq!(lists_found.len(), 1usize);
         assert_eq!(lists_found[0], local_node_list);

         assert_ne!(local_node.try_reveal(), None);

      }

   }
}

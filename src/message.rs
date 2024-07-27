// Encryption
use ed25519_dalek::{SigningKey, Signature, VerifyingKey, Signer, Verifier};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key
};

// Serialization
use serde::{Serialize, Deserialize};

// Error handling
use crate::{ERR, error::{Err, ErrType, ErrSrc}};
use crate::error;

use crate::node::{Node, NodeDown};

use rand::random;

#[derive(Serialize, Deserialize, Debug)]
/// Defines the protocol and allows for differentiation of packets.
pub enum Message {
   /// Begins the generation of a new consensus.
   Initiate(SharedNonce),
   Block(Block),
   //RequestBlock(IdentityKey, SharedNonce),
   //RespondBlock(IdentityKey, Block),
   List(List),
   //RequestList(IdentityKey, SharedNonce),
   //RespondList(IdentityKey, List),
   //RequestReveal(IdentityKey, SharedNonce),
   /// Shares a reveal key and identifies the block it belongs to.
   Reveal(IdentityKey, SharedNonce, Vec<u8>),
   // Disconnect,
}

// Reduce some code duplication
macro_rules! verify_sig {
   ($s:expr) => {
      let signature = Signature::from_components($s.signature[0], $s.signature[1]);

      // Alternatively, the identity key on the block could be used here
      match VerifyingKey::from_bytes(&$s.identity_key) {
         Err(_) => return Status::Invalid,
         Ok(identity_key) => {
            match identity_key.verify(&$s.to_bytes(), &signature) {
               Ok(_) => {
                  ();
               }
               Err(_err) => return Status::Invalid,
            }
         }
      }
   };
}

/// Indicates the result of `Block` or `List` verification, as a node
/// might relay another its own of these.
#[derive(Debug, Eq, PartialEq)]
pub enum Status {
   /// The block or list is signed by a peer node.
   Peer,
   /// The block or list is signed by this node.
   Me,
   /// The block or list has an invalid signature.
   Invalid,
}

/// A one-time public identifier for each consensus. It is the responsibility of the user
/// to make sure that it is never repeated.
// TODO: Support disk caching.
pub type SharedNonce = [u8; 16];

/// VerifyingKey as bytes. Will be deprecated soon, I didn't know it implemented `Serialize`/`Deserialize`.
// TODO: Remove this
pub type IdentityKey = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
/// An encrypted, signed random number that can be revealed later.
/// # Example
/// ```
/// use rand_num_consensus::{Block, SharedNonce, NodeDown, Node, Status};
/// use rand::random;
/// use ed25519_dalek::SigningKey;
///
/// // Node creates a new block
/// let shared_nonce: SharedNonce = random::<[u8; 16]>();
/// let node_signing_key = SigningKey::from(random::<[u8; 32]>());
/// let (block, reveal_key) = Block::new(&shared_nonce, &node_signing_key);
/// let mut node = NodeDown::default();
/// node.identity_key = node_signing_key.verifying_key();
///
/// // Node then sends the consensus to a peer
///
/// // Peer verifies it
/// assert_eq!(block.verify(&vec![&mut node as &mut dyn Node], &SigningKey::from(random::<[u8; 32]>()).verifying_key()), Status::Peer);;
/// block.reveal(&reveal_key.to_vec()).expect("Could not verify block!");
/// ```
pub struct Block {
   // Identifies the owner of this block
   identity_key: [u8; 32],
   // aes encrypts with 16-byte blocks, so a shared nonce any smaller than
   // 16 bytes in this case is a waste of bandwidth
   shared_nonce: SharedNonce,
   // aes nonce
   nonce: [u8; 12],
   encrypted_number: Vec<u8>,
   // Serde derive doesn't work with arrays of over 32 elements
   signature: [[u8; 32]; 2],

}

impl Block {
   /// Create a new `Block` for this `SharedNonce` and sign it with a local node's signing key.
   /// A single node should never create more than one `Block` for each `SharedNonce`, as this
   /// may hurt the performance of the consensus protocol or cause it to fail (in fact, this is a
   /// potential DOS attack).
   pub fn new(shared_nonce: &SharedNonce, signing_key: &SigningKey) -> (Self, Key<Aes256Gcm>) {
      let block_key = Aes256Gcm::generate_key(OsRng);
      let cipher = Aes256Gcm::new(&block_key);

      let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                                                               // Should never panic
      let random_number = rand::random::<[u8; 32]>();
      let encrypted_number: Vec<u8> = cipher.encrypt(&nonce, &random_number[..]).unwrap();

      // concat slices
      let mut block_wo_auth = Vec::<u8>::from(&signing_key.verifying_key().to_bytes()[..]);
      block_wo_auth.extend_from_slice(&shared_nonce[..]);
      block_wo_auth.extend_from_slice(&nonce[..]);
      block_wo_auth.extend_from_slice(&encrypted_number[..]);

      let signature = signing_key.sign(&block_wo_auth);
      let identity_key = signing_key.verifying_key();
      let block = Block {
         identity_key: identity_key.to_bytes(),
         shared_nonce: shared_nonce.clone(),
         nonce: <[u8; 12]>::from(nonce),
         encrypted_number,
         // no special reason for splitting the signature by r and s components,
         // just Serde derive doesn't work with arrays of more than 32 elements
         signature: [*signature.r_bytes(), *signature.s_bytes()],
      };

      return (block, block_key);
   }

   /// Attempt to verify and add this block to a `Node` implementor, consuming it.
   /// # Parameters
   /// `keyring`: a vector of offline and/or connected nodes. \
   /// `local_node_ik`: the signing key of the local node, used to check if this block is it's own. \
   /// Returns `Status::Me` if a peer relayed the local node's block.
   pub fn add(self, keyring: Vec<&mut (dyn Node)>, local_node_ik: &VerifyingKey) -> Status {

      // Reduce code duplication
      verify_sig!(self);

      for node in keyring {
         if self.identity_key() == node.identity_key().as_bytes() {
            node.blocks_mut().push(self);
            return Status::Peer;
         }
      }
      if self.identity_key() == local_node_ik.as_bytes() {
         return Status::Me;
      }

      return Status::Invalid;

   }

   /// Attempt to verify a block without consuming it.
   pub fn verify(&self, keyring: &Vec<&mut (dyn Node)>, local_node_ik: &VerifyingKey) -> Status {

      // Reduce code duplication
      verify_sig!(self);

      for node in keyring {
         if self.identity_key() == node.identity_key().as_bytes() {
            return Status::Peer;
         }
      }
      if self.identity_key() == local_node_ik.as_bytes() {
         return Status::Me;
      }

      return Status::Invalid;
   }

   /// Convert this block to bytes, excluding the signature.
   pub fn to_bytes(&self) -> Vec<u8> {
      // concat slices
      let mut block_wo_auth = Vec::<u8>::new();
      block_wo_auth.extend_from_slice(&self.identity_key[..]);
      block_wo_auth.extend_from_slice(&self.shared_nonce[..]);
      block_wo_auth.extend_from_slice(&self.nonce[..]);
      block_wo_auth.extend_from_slice(&self.encrypted_number[..]);
      return block_wo_auth;
   }

   // Immutable getters
   pub fn identity_key(&self) -> &[u8; 32] { return &self.identity_key }
   pub fn shared_nonce(&self) -> &SharedNonce { return &self.shared_nonce }

   /// Attempt to reveal this block with a reveal key.
   /// # Errors
   /// `Err::Reveal`: the reveal key was invalid or did not sucessfully decrypt the number.
   pub fn reveal(&self, reveal_key: &Vec<u8>) -> Result<[u8; 32], Err> {
      let cipher = Aes256Gcm::new_from_slice(&reveal_key[..])
         .map_err(|_| ERR!("Invalid reveal key", Reveal))?;
      let number = cipher.decrypt(&self.nonce.into(), &self.encrypted_number[..])
         .map_err(|_| ERR!("Could not reveal number", Reveal))?;
      return Ok(number.try_into().unwrap());
   }
}

impl std::cmp::Ord for Block {
   fn cmp(&self, other: &Self) -> std::cmp::Ordering {
      // Should never panic...
      return <u128>::from_be_bytes(<[u8; 16]>::try_from(&self.encrypted_number[..16]).unwrap())
         .cmp(&<u128>::from_be_bytes(<[u8; 16]>::try_from(&other.encrypted_number[..16]).unwrap()));
   }
}

impl std::cmp::PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        return Some(self.cmp(other));
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq/*, PartialEq*/)]
/// A signed, unordered list of `Block`s.
pub struct List {
   identity_key: [u8; 32],
   blocks: Vec<Block>,
   signature: [[u8; 32]; 2],
}

impl List {
   /// Convert this list to bytes, excluding the attached identity key and signature.
   pub fn to_bytes(&self) -> Vec<u8> {
      let mut blocks_bytes = Vec::<u8>::new();
      for block in &self.blocks {
         blocks_bytes.extend_from_slice(&block.to_bytes()[..]);
      }
      return blocks_bytes;
   }

   /// Create a new `List` by searching for blocks with the same `SharedNonce`.
   /// If a list could not be created, this function returns a vector of identity keys to use to
   /// request them from a connected node using `Message::RequestBlock` (not yet implemented).
   /// It is necessary to call `.sign()` after creating a new `List` for it to be accepted by
   /// other nodes as valid.
   /// # Parameters
   /// `all_nodes`: a vector of offline and/or connected nodes. \
   /// `identity_key`: the verifying (public/identity) key of the local node. \
   /// `shared_nonce`: the shared nonce used to look for blocks. \
   /// `self_block`: the block from the local node to add to the list. \
   pub fn new(mut all_nodes: Vec<&mut (dyn Node)>, identity_key: VerifyingKey, shared_nonce: &SharedNonce, self_block: Block) -> Result<Self, Vec<IdentityKey>> {
      let mut list = List {
         identity_key: identity_key.to_bytes(),
         blocks: Vec::<Block>::new(),
         signature: [[0u8; 32]; 2],
      };
      let mut request_blocks = Vec::<IdentityKey>::new();
      // Use indicies to avoid moving any values before it is known
      // a that List can be created sucessfully
      let mut indicies = Vec::<usize>::new();

      'nodes: for node in &all_nodes {
         for j in 0..node.blocks().len() {
            if &node.blocks()[j].shared_nonce == shared_nonce {
               indicies.push(j);
               continue 'nodes;
            }
         }
         // Check if an online node can supply the block
         request_blocks.push(node.identity_key().clone().to_bytes());
      }

      // FIXME: Allow this consensus to continue even if not all blocks are present, like how
      // it is with lists
      if request_blocks.len() == 0 {
         for (index, node) in all_nodes.iter_mut().enumerate() {
            list.blocks.push(node.blocks_mut().remove(indicies[index]));
         }
         list.blocks.push(self_block);
         return Ok(list);
      }
      else {
         return Err(request_blocks);
      }



   }

   // FIXME: Combine sign() with new()
   pub fn sign(&mut self, signing_key: &SigningKey) {
      // Make sure the identity matches the signature,
      //if this block is being resigned for some reason
      self.identity_key = signing_key.verifying_key().to_bytes();

      let mut blocks_bytes = Vec::<u8>::new();
      for block in &self.blocks {
         blocks_bytes.extend_from_slice(&block.to_bytes()[..]);
      }

      let signature = signing_key.sign(&blocks_bytes);
      // no special reason for splitting the signature by r and s components,
      // just Serde derive doesn't work with arrays of more than 32 elements
      self.signature = [*signature.r_bytes(), *signature.s_bytes()];
   }

   /// Verifies and adds this list to a `Node` implementor.
   /// # Errors
   /// Throws `Status::Invalid` if
   /// this object already stores an identical list, a list that matches this list's `SharedNonce`,
   /// if its identity key does not match any from the keyring, if the signature is invalid,
   /// if any block is not unique, if not all its blocks' `SharedNonce`s match, or any block
   /// could not be verified.
   pub fn add(self, mut keyring: Vec<&mut (dyn Node)>, local_node_ik: &VerifyingKey) -> Status {
      let mut seen_before = Vec::<&[u8; 32]>::new();
      let mut key_is_trusted = false;
      let mut node_index = 0usize;
      for i in 0..keyring.len() {
         if self.identity_key() == keyring[i].identity_key().as_bytes() {
            if keyring[i].lists().contains(&self) {
               return Status::Invalid;
            }
            else if let Some(_) = keyring[i].lists().iter().find(|&list| list.blocks[0].shared_nonce() == &self.blocks[0].shared_nonce) {
               return Status::Invalid;
            }

            key_is_trusted = true;
            node_index = i;
            break;
         }
      }
      if !key_is_trusted { return Status::Invalid }
      if self.identity_key() == local_node_ik.as_bytes() {
         return Status::Me;
      }

      verify_sig!(self);

      for block in &self.blocks {
         if let Status::Invalid = block.verify(&keyring, local_node_ik) {
            return Status::Invalid;
         }
         // Double reference...?
         else if seen_before.contains(&&block.identity_key) {
            return Status::Invalid;
         }
         else if block.shared_nonce != self.blocks[0].shared_nonce {
            return Status::Invalid;
         }
         else {
            seen_before.push(&block.identity_key);
         }
      }

      // FIXME: Allow this consensus to continue even if not all blocks are present, like how
      // it is with lists
      if seen_before.len() < keyring.len() {
         // not all nodes have contributed a block
         return Status::Invalid;
      }
      else {
         keyring[node_index].lists_mut().push(self);
         return Status::Peer;
      }

   }

   // Immutable getter
   pub fn identity_key(&self) -> &[u8; 32] { return &self.identity_key }
   pub fn blocks(&self) -> &Vec<Block> { return &self.blocks }
   // all blocks should have the same SharedNonce
   pub fn shared_nonce(&self) -> &SharedNonce { return &self.blocks[0].shared_nonce }
}

impl std::cmp::PartialEq for List {
   fn eq(&self, other: &List) -> bool {
      // Compare blocks
      for block in &self.blocks {
         if other.blocks.contains(block) {
            continue;
         }
         else { return false }
      }

      // Two empty lists are also equal
      if self.blocks.len() == other.blocks.len() {
         return true;
      }
      else {
         return false;
      }
   }
}

impl std::hash::Hash for List {
   fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
      // Sort the blocks in an arbitrary but consistent order
      let mut sorted_blocks = self.blocks.clone();
      sorted_blocks.sort();
      for block in sorted_blocks {
         block.hash(state);
      }

   }
}

// FIXME: better name: Fragment? or Endorsement?
#[derive(Serialize, Deserialize, Debug)]
/// A signed consensus that can be sent to the client.
/// # Example
/// ```
/// use rand_num_consensus::{Consensus, SharedNonce};
/// use rand::random;
/// use ed25519_dalek::SigningKey;
///
/// // Node endorses a number for the consensus
/// let shared_nonce: SharedNonce = random::<[u8; 16]>();
/// let node_signing_key = SigningKey::from(random::<[u8; 32]>());
/// let node_consensus = random::<[u8; 32]>();
/// let consensus = Consensus::new(&node_signing_key, node_consensus.clone(), shared_nonce);
///
/// // Node then sends the consensus to a client
///
/// // Client verifies it
/// assert!(consensus.verify(&vec![node_signing_key.verifying_key()]));
/// assert_eq!(&node_consensus, consensus.number());
/// ```
pub struct Consensus {
   identity_key: [u8; 32],
   shared_nonce: SharedNonce,
   number: [u8; 32],
   signature: [[u8; 32]; 2],
}

impl Consensus {
   /// Endorse a number for this consensus (identified using the shared nonce).
   pub fn new(signing_key: &SigningKey, number: [u8; 32], shared_nonce: SharedNonce) -> Self {
      let bytes = number.iter().chain(shared_nonce.iter()).cloned().collect::<Vec<u8>>();
      let signature = signing_key.sign(&bytes);
      return Consensus {
         identity_key: signing_key.verifying_key().to_bytes(),
         shared_nonce,
         number,
         signature: [*signature.r_bytes(), *signature.s_bytes()],
      }
   }

   /// Verify this consensus on the client. The keyring should include the identity keys of the nodes
   /// that participated in it.
   pub fn verify(&self, keyring: &Vec<VerifyingKey>) -> bool {
      let bytes = self.number.iter().chain(self.shared_nonce.iter()).cloned().collect::<Vec<u8>>();
      if let Some(key) = keyring.iter().find(|key| key.as_bytes() == &self.identity_key) {
         if let Ok(()) = key.verify(&bytes, &Signature::from_components(self.signature[0], self.signature[1])) {
            return true;
         }
         else { return false };
      }
      else {
         return false;
      }

   }

   /// Get the random number chosen in this consensus.
   pub fn number(&self) -> &[u8; 32] { return &self.number }
   pub fn shared_nonce(&self) -> &SharedNonce { return &self.shared_nonce }
}

impl std::cmp::PartialEq for Consensus {
   fn eq(&self, other: &Consensus) -> bool {
      return &self.number== other.number()
         && &self.shared_nonce == other.shared_nonce();
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_block_new_and_verify() {
      let shared_nonce: SharedNonce = random::<[u8; 16]>();
      let signing_key = SigningKey::from(random::<[u8; 32]>());
      let mut node: NodeDown = Default::default();
      node.identity_key = signing_key.verifying_key();

      let (new_block, reveal_key) = Block::new(&shared_nonce, &signing_key);
                                                                     // Arbitrary placeholder value
      assert_eq!(new_block.verify(&vec![&mut node as &mut (dyn Node)], &SigningKey::from(random::<[u8; 32]>()).verifying_key()), Status::Peer);
      new_block.reveal(&reveal_key.to_vec()).unwrap();
   }

   #[test]
   fn test_consensus_eq() {
      let shared_nonce_1: SharedNonce = random::<[u8; 16]>();
      let shared_nonce_2: SharedNonce = random::<[u8; 16]>();
      let random_number_1 = random::<[u8; 32]>();
      let random_number_2 = random::<[u8; 32]>();

      let consensus_1 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_2.clone(), shared_nonce_2.clone());
      let consensus_2 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_2.clone(), shared_nonce_2.clone());

      assert_eq!(consensus_1, consensus_2);

      let consensus_3 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_2.clone(), shared_nonce_2.clone());
      let consensus_4 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_2.clone(), shared_nonce_1.clone());

      assert_ne!(consensus_3, consensus_4);

      let consensus_5 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_2.clone(), shared_nonce_2.clone());
      let consensus_6 = Consensus::new(&SigningKey::from(random::<[u8; 32]>()), random_number_1.clone(), shared_nonce_2.clone());

      assert_ne!(consensus_5, consensus_6);
   }

}

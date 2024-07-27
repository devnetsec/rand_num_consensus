use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq)]
// FIXME: more info here
/// The error handling type for the entire crate.
pub struct Err {
    pub source: ErrSrc,
}

// Required impl
impl Error for Err {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        return Some(&self.source);
    }
}

// Required impl
impl fmt::Display for Err {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source.err_type {
            ErrType::Connect(_err) => write!(f, "While connecting: {_err}"),
            ErrType::Other(_err) => write!(f, "{_err}"),
            ErrType::Packet(_err) => write!(f, "While processing a packet: {_err}"),
            ErrType::Broadcast(_err) => write!(f, "While broadcasting a message: {_err}"),
            ErrType::Reveal(_err) => write!(f, "While revealing a block: {_err}"),
            ErrType::Start(_err) => write!(f, "While starting a local node: {_err}"),
        }

    }
}

impl<T> From<Result<T, Err>> for Err {
    fn from(err: Result<T, Err>) -> Err {
        // FIXME: should always be true?
        if let Err(err) = err { return err }
        else {
            // FIXME: Not sure when this case will be reached
            panic!("Fatal error while proprogating error");
        }
    }
}

#[derive(Debug, PartialEq)]
#[doc(hidden)]
pub struct ErrSrc {
    pub err_type: ErrType,
}

impl fmt::Display for ErrSrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.err_type {
            ErrType::Connect(_err) => write!(f, "While connecting: {_err}"),
            ErrType::Other(_err) => write!(f, "{_err}"),
            ErrType::Packet(_err) => write!(f, "While processing a packet: {_err}"),
            ErrType::Broadcast(_err) => write!(f, "While broadcasting a message: {_err}"),
            ErrType::Reveal(_err) => write!(f, "While revealing a block: {_err}"),
            ErrType::Start(_err) => write!(f, "While starting a local node: {_err}"),
        }

    }
}

impl Error for ErrSrc {}

#[derive(Debug, PartialEq)]
/// Indicates the type of error so they can be used to trigger certain logic.
pub enum ErrType {
    /// An encrypted connection could not be created.
    Connect(String),
    //Initiate(String),
    /// A packet could not be en/decrypted, (de)serialized, or sent/received.
    Packet(String),
    /// A local node could not be started (likely an OS error).
    Start(String),
    /// There was an error that prevented a full broadcast. There may be multiple of these when calling `broadcast()`, and printing all of them may be too verbose.
    Broadcast(String),
    /// A reveal key either could not be broadcasted or could not be used to reveal a block.
    Reveal(String),
    Other(String),
}

#[macro_export]
/// Instantiate an error object using prettier syntax.  \
/// # Parameters
/// $l: Error string \
/// $t: [`ErrType`] \
/// $e: Nested error
macro_rules! ERR {
    ($l:literal, $t:ident, $e:expr) => {
        error::Err { source: ErrSrc { err_type: ErrType::$t($l.to_string() + format!(": {:?}", $e).as_str())} }
    };

    ($l:expr, $t:ident, $e:expr) => {
        error::Err { source: ErrSrc { err_type: ErrType::$t($l.to_string() + format!(": {:?}", $e).as_str())} }
    };

    ($l:literal, $t:ident) => {
        error::Err { source: ErrSrc { err_type: ErrType::$t($l.to_string())} }

    };

    ($l:literal) => {
        error::Err { source: ErrSrc { err_type: ErrType::Other($l.to_string())} }
    };

    ($t:ident, $e:expr) => {
        error::Err { source: ErrSrc { err_type: ErrType::$t($e.to_string())} }

    };

    ($e:expr) => {
        error::Err { source: ErrSrc { err_type: ErrType::Other($e.to_string())} }

    };
}

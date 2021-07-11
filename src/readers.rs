//! Support for enumerating available readers

use crate::{Result, YubiKey};
use std::{
    borrow::Cow,
    convert::TryInto,
    ffi::CStr,
    sync::{Arc, Mutex},
};

/// Iterator over connected readers
pub type Iter<'ctx> = std::vec::IntoIter<Reader<'ctx>>;

/// Enumeration support for available readers
pub struct Readers {
    /// PC/SC context
    ctx: Arc<Mutex<pcsc::Context>>,

    /// Buffer for storing reader names
    reader_names: Vec<u8>,
}

impl Readers {
    /// Open a PC/SC context, which can be used to enumerate available PC/SC
    /// readers (which can be used to connect to YubiKeys).
    pub fn open() -> Result<Self> {
        let ctx = pcsc::Context::establish(pcsc::Scope::System)?;
        let reader_names = vec![0u8; ctx.list_readers_len()?];
        Ok(Self {
            ctx: Arc::new(Mutex::new(ctx)),
            reader_names,
        })
    }

    /// Iterate over the available readers
    pub fn iter(&mut self) -> Result<Iter<'_>> {
        let Self { ctx, reader_names } = self;

        let reader_cstrs: Vec<_> = {
            let c = ctx.lock().unwrap();

            // ensure PC/SC context is valid
            c.is_valid()?;

            c.list_readers(reader_names)?.collect()
        };

        let readers: Vec<_> = reader_cstrs
            .iter()
            .map(|name| Reader::new(name, Arc::clone(ctx)))
            .collect();

        Ok(readers.into_iter())
    }
}

/// An individual connected reader
pub struct Reader<'ctx> {
    /// Name of this reader
    name: &'ctx CStr,

    /// PC/SC context
    ctx: Arc<Mutex<pcsc::Context>>,
}

impl<'ctx> Reader<'ctx> {
    /// Create a new reader from its name and context
    fn new(name: &'ctx CStr, ctx: Arc<Mutex<pcsc::Context>>) -> Self {
        // TODO(tarcieri): open devices, determine they're YubiKeys, get serial?
        Self { name, ctx }
    }

    /// Get this reader's name
    pub fn name(&self) -> Cow<'_, str> {
        // TODO(tarcieri): is lossy ok here? try to avoid lossiness?
        self.name.to_string_lossy()
    }

    /// Open a connection to this reader, returning a `YubiKey` if successful
    pub fn open(&self) -> Result<YubiKey> {
        self.try_into()
    }

    /// Connect to this reader, returning its `pcsc::Card`
    pub(crate) fn connect(&self) -> Result<pcsc::Card> {
        let ctx = self.ctx.lock().unwrap();
        Ok(ctx.connect(self.name, pcsc::ShareMode::Shared, pcsc::Protocols::T1)?)
    }
}

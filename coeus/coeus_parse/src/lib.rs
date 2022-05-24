//! This module provides functions to extract zips and parse dex files. Further it provides functions to obtain and work on graphs, especially the information-graph.
pub mod dex;
pub mod extraction;

#[cfg(feature = "rhai-script")]
pub mod scripting;

pub use coeus_emulation;
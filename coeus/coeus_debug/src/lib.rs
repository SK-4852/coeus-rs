// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::Read;

use coeus_models::models::CodeItem;
use jdwp::JdwpClient;
pub use tokio::runtime::Runtime;

pub mod jdwp;
pub mod models;

pub(crate) trait FromBytes {
    type ResultObject;
    type ErrorObject;
    fn from_bytes<R>(buf: &mut R) -> Result<Self::ResultObject, Self::ErrorObject>
    where
        R: Read;
}
pub(crate) trait ToBytes {
    type ErrorObject;
    fn bytes(&self) -> Result<Vec<u8>, Self::ErrorObject>;
}

pub fn get_code_indizes_from_code(code_item: &CodeItem) -> Vec<u32> {
    code_item
        .insns
        .iter()
        .map(|(_, offset, _)| offset.0)
        .collect()
}

pub fn create_debugger(host: &str, port: u16) -> anyhow::Result<(JdwpClient, Runtime)> {
    jdwp::JdwpClient::new(host, port)
}

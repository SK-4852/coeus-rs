// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    io::{Cursor, Read, Write},
};

use anyhow::bail;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use tokio::{
    net::TcpStream,
    runtime::{self, Builder, Runtime},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    models::{
        Class, JdwpCommandPacket, JdwpEventType, JdwpPacket, JdwpReplyPacket, Location, Method,
        Slot, VariableTable, VmType,
    },
    FromBytes, ToBytes,
};

pub struct JdwpClient {
    read_thread: JoinHandle<anyhow::Result<()>>,
    write_thread: JoinHandle<anyhow::Result<()>>,
    tx: UnboundedSender<JdwpPacket>,
    rx: UnboundedReceiver<JdwpPacket>,
    field_id_size: u32,
    method_id_size: u32,
    object_id_size: u32,
    reference_type_id_size: u32,
    frame_id_size: u32,
}
// Private interface
impl JdwpClient {
    async fn get_id_sizes(&mut self) -> anyhow::Result<()> {
        let id_package = JdwpCommandPacket::id_sizes(1);
        self.send_cmd(JdwpPacket::CommandPacket(id_package))?;
        let Some(JdwpPacket::ReplyPacket(reply)) = self.rx.recv().await else {
            bail!("Wrong packer");
        };
        if reply.is_error() {
            bail!("{}", reply.get_error());
        }
        let mut data_cursor = Cursor::new(reply.get_data());
        self.field_id_size = data_cursor.read_u32::<BigEndian>()?;
        self.method_id_size = data_cursor.read_u32::<BigEndian>()?;
        self.object_id_size = data_cursor.read_u32::<BigEndian>()?;
        self.reference_type_id_size = data_cursor.read_u32::<BigEndian>()?;
        self.frame_id_size = data_cursor.read_u32::<BigEndian>()?;
        Ok(())
    }
    async fn deserialize_class(&mut self, reply: JdwpReplyPacket) -> anyhow::Result<Vec<Class>> {
        let mut classes = vec![];
        let mut data_cursor = Cursor::new(reply.get_data());
        let number_of_classes = data_cursor.read_u32::<BigEndian>()?;
        for _ in 0..number_of_classes {
            let type_tag = data_cursor.read_u8()?;
            let mut ref_type_id = vec![0; self.reference_type_id_size as usize];
            data_cursor.read_exact(&mut ref_type_id)?;
            let status = data_cursor.read_u32::<BigEndian>()?;
            let mut ref_type = [0u8; 8];
            ref_type.copy_from_slice(&ref_type_id[..8]);
            let ref_type = u64::from_be_bytes(ref_type);

            let mut c = Class {
                ty: type_tag.try_into()?,
                ref_type,
                status,
                methods: HashMap::new(),
            };
            let methods = self.get_methods(c.get_id()).await?;
            c.methods = methods
                .into_iter()
                .map(|m| (format!("{}{}", m.get_name(), m.get_signature()), m))
                .collect();
            classes.push(c);
        }
        Ok(classes)
    }
    async fn get_methods(&mut self, reference_id: u64) -> anyhow::Result<Vec<Method>> {
        let get_methods = JdwpCommandPacket::get_methods(3, reference_id);
        self.send_cmd(JdwpPacket::CommandPacket(get_methods))?;
        let Some(JdwpPacket::ReplyPacket(reply)) = self.rx.recv().await  else {
            bail!("no reply");
        };
        if reply.is_error() {
            bail!("{}", reply.get_error());
        }
        let mut methods = vec![];
        let mut reply_cursor = Cursor::new(reply.get_data());
        let num_methods = reply_cursor.read_u32::<BigEndian>()?;
        for _ in 0..num_methods {
            let method_id = reply_cursor.read_u64::<BigEndian>()?;
            let name_len = reply_cursor.read_u32::<BigEndian>()?;
            let mut name_buffer = vec![0u8; name_len as usize];
            reply_cursor.read_exact(&mut name_buffer)?;
            let name = std::str::from_utf8(&name_buffer)?.to_string();

            let sig_len = reply_cursor.read_u32::<BigEndian>()?;
            let mut sig_buffer = vec![0u8; sig_len as usize];
            reply_cursor.read_exact(&mut sig_buffer)?;
            let signature = std::str::from_utf8(&sig_buffer)?.to_string();
            let mod_bits = reply_cursor.read_u32::<BigEndian>()?;
            let variable_table = match self.get_variable_table(reference_id, method_id).await {
                Ok(vt) => vt,
                Err(_) => VariableTable {
                    arg_count: 0,
                    slots: vec![],
                },
            };

            methods.push(Method {
                method_id,
                name,
                signature,
                mod_bits,
                variable_table,
            })
        }
        Ok(methods)
    }
    async fn get_variable_table(
        &mut self,
        class_id: u64,
        method_id: u64,
    ) -> anyhow::Result<VariableTable> {
        let cmd = JdwpCommandPacket::get_variable_table(10, class_id, method_id)?;
        self.send_cmd(JdwpPacket::CommandPacket(cmd))?;
        let reply = self
            .wait_for_package()
            .await
            .ok_or_else(|| anyhow::Error::msg("No answer"))?;
        let JdwpPacket::ReplyPacket(reply) = reply else {
            panic!("Wrong packet");
        };
        if reply.is_error() {
            bail!("{}", reply.get_error());
        }
        reply.try_into()
    }

    async fn get_reference_type(&mut self, object_id: u64) -> anyhow::Result<u64> {
        let cmd = JdwpCommandPacket::get_reference_type(10, object_id)?;
        self.send_cmd(JdwpPacket::CommandPacket(cmd))?;
        let reply = self
            .wait_for_package()
            .await
            .ok_or_else(|| anyhow::Error::msg("No answer"))?;
        let JdwpPacket::ReplyPacket(reply) = reply else {
            panic!("Wrong packet");
        };
        let mut reader = Cursor::new(reply.get_data());
        let _ = reader.read_u8()?;
        let reference_id = reader.read_u64::<BigEndian>()?;
        Ok(reference_id)
    }
}

impl JdwpClient {
    pub fn close(&mut self) {
        self.read_thread.abort();
        self.write_thread.abort();
    }
    pub fn new(addr: &str, port: u16) -> anyhow::Result<(Self, Runtime)> {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let rt = Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("debugger-thread")
            .thread_stack_size(3 * 1024 * 1024)
            .enable_all()
            .build()
            .unwrap();
        let mut tcp_handle =
            rt.block_on(async { TcpStream::connect(format!("{}:{}", addr, port)).await })?;

        let mut tcp_handle = rt.block_on(async move {
            tcp_handle.write_all(b"JDWP-Handshake").await?;
            let mut handshake_answer = vec![0u8; 14];
            tcp_handle.read_exact(&mut handshake_answer).await?;
            if &handshake_answer != b"JDWP-Handshake" {
                bail!("wrong handshake answer");
            }
            Ok(tcp_handle)
        })?;

        let (mut reader, mut writer) = tcp_handle.into_split();
        let (reader_tx, reader_rx) = tokio::sync::mpsc::unbounded_channel::<JdwpPacket>();
        let (writer_tx, mut writer_rx) = tokio::sync::mpsc::unbounded_channel::<JdwpPacket>();

        let read_thread = rt.spawn(async move {
            loop {
                let Ok(length) = reader.read_u32().await else {
                    log::error!("failed to read length");
                    continue;
                };
                let mut buf = vec![0; length as usize];
                buf[0..4].copy_from_slice(&length.to_be_bytes());
                let Ok(_) = reader.read_exact(&mut buf[4..]).await else {
                    log::error!("failed to fill buffer");
                    continue;
                };
                let Ok(reply_packet) = JdwpReplyPacket::from_bytes(&mut Cursor::new(&buf)) else {
                    log::error!("could not parse packet: {:?}", buf);
                    continue;
                };
                match reply_packet.get_flags() {
                    0x80 => reader_tx.send(JdwpPacket::ReplyPacket(reply_packet))?,
                    _ => {
                        let Ok(command_packet) = JdwpCommandPacket::from_bytes(&mut Cursor::new(&buf)) else {
                            continue;
                        };

                        reader_tx.send(JdwpPacket::CommandPacket(command_packet))?;
                    }
                };
            }
        });
        let write_thread = rt.spawn(async move {
            loop {
                if let Some(pkg) = writer_rx.recv().await {
                    writer.write_all(&pkg.bytes()?).await?;
                }
            }
        });
        let mut client = Self {
            read_thread,
            write_thread,
            tx: writer_tx,
            rx: reader_rx,
            field_id_size: 0,
            method_id_size: 0,
            object_id_size: 0,
            reference_type_id_size: 0,
            frame_id_size: 0,
        };
        let client = rt.block_on(async move {
            client.get_id_sizes().await?;
            let Ok(_) = client.get_version_info().await else {
                bail!("Could not get version info")
            };
            Ok(client)
        })?;

        Ok((client, rt))
    }

    pub fn get_version_info_blocking(&mut self, runtime: &Runtime) -> anyhow::Result<String> {
        runtime.block_on(self.get_version_info())
    }

    pub async fn get_version_info(&mut self) -> anyhow::Result<String> {
        let version_package = JdwpCommandPacket::version(1);
        self.send_cmd(JdwpPacket::CommandPacket(version_package))?;
        let Some(JdwpPacket::ReplyPacket(reply)) = self.wait_for_package().await else {
                bail!("could not get version");
        };

        let mut data_cursor = Cursor::new(reply.get_data());
        let length = data_cursor.read_u32::<BigEndian>()?;
        let mut description = vec![0; length as usize];
        data_cursor.read_exact(&mut description)?;
        let jdwp_major = data_cursor.read_u32::<BigEndian>()?;
        let jdwp_minor = data_cursor.read_u32::<BigEndian>()?;

        let length = data_cursor.read_u32::<BigEndian>()?;
        let mut vm_version = vec![0; length as usize];
        data_cursor.read_exact(&mut vm_version)?;
        let vm_version = String::from_utf8(vm_version)?;

        let length = data_cursor.read_u32::<BigEndian>()?;
        let mut vm_name = vec![0; length as usize];
        data_cursor.read_exact(&mut vm_name)?;
        let vm_name = String::from_utf8(vm_name)?;

        let description = String::from_utf8(description)?;
        return Ok(format!(
            "{}\n{}.{}\n{}\n{}",
            description, jdwp_major, jdwp_minor, vm_version, vm_name
        ));
    }

    pub fn get_class(&mut self, runtime: &Runtime, signature: &str) -> anyhow::Result<Vec<Class>> {
        runtime.block_on(async {
            let class_package = JdwpCommandPacket::classes_by_signature(3, signature);
            self.send_cmd(JdwpPacket::CommandPacket(class_package))?;
            let pkg = self.wait_for_package().await;
            let Some(JdwpPacket::ReplyPacket(reply)) = pkg else {
            bail!("Wrong packet: {:?}", pkg);
        };
            self.deserialize_class(reply).await
        })
    }

    pub fn get_all_classes(&mut self, runtime: &Runtime) -> anyhow::Result<Vec<Class>> {
        runtime.block_on(async {
            let id_package = JdwpCommandPacket::all_classes(3);
            self.send_cmd(JdwpPacket::CommandPacket(id_package))?;
            let Some(JdwpPacket::ReplyPacket(reply)) = self.wait_for_package().await else {
            bail!("Wrong packet");
            };
            self.deserialize_class(reply).await
        })
    }

    pub fn set_breakpoint(
        &mut self,
        runtime: &Runtime,
        cmd: JdwpCommandPacket,
    ) -> anyhow::Result<()> {
        runtime.block_on(async {
            self.send_cmd(JdwpPacket::CommandPacket(cmd))?;
            let pkg = self.wait_for_package().await;
            let Some(JdwpPacket::ReplyPacket(reply)) = pkg else {
            bail!("Wrong packet: {:?}", pkg);
        };
            if reply.is_error() {
                bail!("SetBreakpoint failed: {}", reply.get_error());
            }
            Ok(())
        })
    }
    pub async fn wait_for_package(&mut self) -> Option<JdwpPacket> {
        self.rx.recv().await
    }
    pub fn wait_for_package_blocking(&mut self, runtime: &Runtime) -> Option<JdwpPacket> {
        runtime.block_on(self.wait_for_package())
    }
    pub fn resume(&mut self, runtime: &Runtime, id: u32) -> anyhow::Result<()> {
        runtime.block_on(async {
            let resume = JdwpCommandPacket::resume(id);
            self.send_cmd(JdwpPacket::CommandPacket(resume))?;
            let Some(JdwpPacket::ReplyPacket(_)) = self.wait_for_package().await else {
            bail!("Wrong packet");
        };
            Ok(())
        })
    }
    pub fn get_string(&mut self, runtime: &Runtime, string_ref: u64) -> anyhow::Result<String> {
        runtime.block_on(async {
            let cmd = JdwpCommandPacket::get_string(10, string_ref)?;
            self.send_cmd(JdwpPacket::CommandPacket(cmd))?;
            if let Some(JdwpPacket::ReplyPacket(reply)) = self.rx.recv().await {
                log::debug!("{:?}", reply);
                let mut data_cursor = Cursor::new(reply.get_data());
                return String::from_bytes(&mut data_cursor);
            }
            Ok(String::new())
        })
    }
    pub fn get_object_signature(
        &mut self,
        runtime: &Runtime,
        object_ref: u64,
    ) -> anyhow::Result<String> {
        runtime.block_on(async {
            let ref_type = self.get_reference_type(object_ref).await?;
            let cmd = JdwpCommandPacket::get_object_signature(10, ref_type)?;
            self.send_cmd(JdwpPacket::CommandPacket(cmd))?;
            if let Some(JdwpPacket::ReplyPacket(reply)) = self.rx.recv().await {
                log::debug!("{:?}", reply);
                let mut data_cursor = Cursor::new(reply.get_data());
                return String::from_bytes(&mut data_cursor);
            }
            Ok(String::new())
        })
    }
    pub fn send_cmd(&mut self, cmd: JdwpPacket) -> anyhow::Result<()> {
        self.tx.send(cmd)?;
        Ok(())
    }
}

impl JdwpCommandPacket {
    pub fn resume(id: u32) -> Self {
        Self {
            length: 11,
            id,
            flags: 0,
            command_set: 1,
            command: 9,
            data: vec![],
        }
    }
    pub fn version(id: u32) -> Self {
        let length = 11;
        Self {
            length,
            id,
            flags: 0,
            command_set: 1,
            command: 1,
            data: vec![],
        }
    }
    pub fn id_sizes(id: u32) -> Self {
        let length = 11;
        Self {
            length,
            id,
            flags: 0,
            command_set: 1,
            command: 7,
            data: vec![],
        }
    }
    pub fn all_classes(id: u32) -> Self {
        let length = 11;
        Self {
            length,
            id,
            flags: 0,
            command_set: 1,
            command: 3,
            data: vec![],
        }
    }

    pub fn classes_by_signature(id: u32, signature: &str) -> Self {
        let string_len = signature.len();
        let mut data = vec![0u8; string_len + 4];
        data[..4].copy_from_slice(&(string_len as u32).to_be_bytes());
        data[4..].copy_from_slice(signature.as_bytes());
        let length = 11 + data.len();
        Self {
            length: length as u32,
            id,
            flags: 0,
            command_set: 1,
            command: 2,
            data,
        }
    }
    pub fn get_methods(id: u32, reference_id: u64) -> Self {
        let ref_id = reference_id.to_be_bytes();
        Self {
            length: 11 + ref_id.len() as u32,
            id,
            flags: 0,
            command_set: 2,
            command: 5,
            data: ref_id.to_vec(),
        }
    }
    pub fn get_variable_table(id: u32, class_id: u64, method_id: u64) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(class_id)?;
        data.write_u64::<BigEndian>(method_id)?;
        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 6,
            command: 2,
            data,
        })
    }
    pub fn get_stack_frames(
        id: u32,
        thread_id: u64,
        start: u32,
        length: i32,
    ) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(thread_id)?;
        data.write_u32::<BigEndian>(start)?;
        data.write_i32::<BigEndian>(length)?;
        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 11,
            command: 6,
            data,
        })
    }
    pub fn get_values(
        id: u32,
        thread_id: u64,
        frame_id: u64,
        slots_in_scope: &[Slot],
    ) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(thread_id)?;
        data.write_u64::<BigEndian>(frame_id)?;
        data.write_u32::<BigEndian>(slots_in_scope.len() as u32)?;
        for slot in slots_in_scope {
            data.write_u32::<BigEndian>(slot.slot_idx)?;
            data.write_u8(VmType::try_from(slot.get_signature())? as u8)?;
        }

        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 16,
            command: 1,
            data,
        })
    }
    pub fn get_string(id: u32, string_ref: u64) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(string_ref)?;

        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 10,
            command: 1,
            data,
        })
    }
    pub fn get_reference_type(id: u32, object_id: u64) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(object_id)?;

        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 9,
            command: 1,
            data,
        })
    }
    pub fn get_object_signature(id: u32, string_ref: u64) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u64::<BigEndian>(string_ref)?;

        Ok(Self {
            length: 11 + data.len() as u32,
            id,
            flags: 0,
            command_set: 2,
            command: 1,
            data,
        })
    }

    pub fn set_breakpoint(id: u32, location: &Location) -> anyhow::Result<Self> {
        let mut data = vec![];
        data.write_u8(JdwpEventType::Breakpoint as u8)?;
        data.write_u8(2u8)?;
        data.write_u32::<BigEndian>(1)?;
        data.write_u8(7)?;
        data.write_all(&location.bytes()?)?;

        let length = 11 + data.len() as u32;
        Ok(Self {
            length,
            id,
            flags: 0,
            command_set: 15,
            command: 1,
            data,
        })
    }
}

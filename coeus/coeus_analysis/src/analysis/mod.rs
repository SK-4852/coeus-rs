use std::{
    convert::{TryFrom},
    sync::Arc,
};

use goblin::elf::Sym;
use regex::Regex;

use coeus_models::models::{BinaryObject, Class, DexFile, Field, Files, Method, Proto};
use serde::Serializer;

use self::{
    dex::find_string_matches_in_dex_with_type,
    native::{find_string_matches_in_elf, BinaryContent},
};

pub mod dex;
pub mod instruction_flow;
pub mod native;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ClassEvidences {
    pub class: Class,
    pub evidences: Vec<Evidence>,
    pub subgraph: Option<String>,
    pub linked: Vec<ClassEvidences>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Evidence {
    String(StringEvidence),
    Instructions(InstructionEvidence),
    CrossReference(CrossReferenceEvidence),
    BytePattern(ByteEvidence),
}
impl Evidence {
    pub fn get_context(&self) -> Option<&Context> {
        match self {
            Evidence::String(se) => Some(&se.context),
            Evidence::Instructions(ie) => Some(&ie.context),
            Evidence::CrossReference(cr) => Some(&cr.context),
            Evidence::BytePattern(_) => None,
        }
    }
    pub fn get_place_context(&self) -> Option<&Context> {
        match self {
            Evidence::CrossReference(cr) => Some(&cr.place_context),
            _ => None,
        }
    }
    pub fn get_location(&self) -> Location {
        match self {
            Evidence::String(se) => se.place.clone(),
            Evidence::Instructions(ie) => ie.place.clone(),
            Evidence::CrossReference(cr) => cr.place.clone(),
            Evidence::BytePattern(bp) => bp.place.clone(),
        }
    }
    pub fn get_instructions(&self) -> Vec<String> {
        if let Evidence::Instructions(ie) = self {
            ie.instructions.clone()
        } else {
            vec![]
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StringEvidence {
    pub content: String,
    pub place: Location,
    pub context: Context,
    pub confidence_level: ConfidenceLevel,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InstructionEvidence {
    pub instructions: Vec<String>,
    pub place: Location,
    pub context: Context,
    pub confidence_level: ConfidenceLevel,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CrossReferenceEvidence {
    pub place: Location,
    pub place_context: Context,
    pub context: Context,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ByteEvidence {
    pub pattern: Vec<BinaryContent>,
    pub place: Location,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]

pub enum Context {
    DexClass(Arc<Class>, Arc<DexFile>),
    #[serde(serialize_with = "class_name")]
    DexMethod(Arc<Method>, Arc<DexFile>),
    DexType(u32, String, Arc<DexFile>),
    DexField(Arc<Field>, Arc<DexFile>),
    DexString(u32, Arc<DexFile>),
    DexProto(Arc<Proto>, Arc<DexFile>),
    DexStaticField(Arc<Field>, Arc<DexFile>),
    NativeSymbol(Arc<BinaryObject>, String),
    #[serde(skip_serializing, skip_deserializing)]
    NativeLib(Arc<BinaryObject>, String, u64, bool, Sym),
    Binary(Arc<BinaryObject>, String),
}
// impl<'a> From<&'a Context> for (Arc<Class>, Arc<DexFile>) {
//     fn from(value: &'a Context) -> Self {
//         if let Context::DexClass(c, f) = value {
//             (c.clone(), f.clone())
//         } else {
//             panic!("Not a class".into())
//         }
//     }
// }
pub type ClassFile = (Arc<Class>, Arc<DexFile>);
impl<'a> TryFrom<&'a Context> for ClassFile {
    type Error = String;

    fn try_from(value: &'a Context) -> Result<Self, Self::Error> {
        if let Context::DexClass(c, f) = value {
            Ok((c.clone(), f.clone()))
        } else {
            Err("Not a class".into())
        }
    }
}

fn class_name<S>(
    method: &Arc<Method>,
    file: &Arc<DexFile>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let type_name = file
        .get_type_name(method.class_idx)
        .unwrap_or("NONE")
        .to_string();
    serializer.serialize_str(&format!("{}->{}", type_name, method.method_name))
}
impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = &mut f.debug_struct("Context");
        match self {
            Context::DexClass(c, _) => f = f.field("class", c),
            Context::DexMethod(m, _) => f = f.field("method", m),
            Context::DexType(_, name, _) => f = f.field("type", name),
            Context::DexProto(p, _) => f = f.field("proto", p),
            _ => f = f.field("obj", &self),
        };
        f.finish()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Location {
    DexString(u32, Arc<DexFile>),
    Class(u32, Arc<DexFile>),
    Type(u32, Arc<DexFile>),
    DexMethod(u32, Arc<DexFile>),
    DexField(u32, Arc<DexFile>),
    NativeSymbol,
    NativeLibLoad,
    NativePattern(String, usize),
    Unknown,
}
impl Location {
    pub fn get_class(&self) -> Option<Arc<Class>> {
        match self {
            Location::Class(class_idx, f) => f.get_class_by_type(*class_idx),
            Location::Type(name_idx, f) => f.get_class_by_type_name_idx(*name_idx),
            Location::DexMethod(method_idx, f) => {
                if let Some(method) = f.get_method_by_idx(*method_idx) {
                    f.get_class_by_type(method.method.class_idx).or_else(|| {
                        Some(Arc::new(Class::new(
                            "NONE".to_string(),
                            0,
                            f.get_type_name(method.method.class_idx)
                                .unwrap_or("NONE")
                                .to_string(),
                        )))
                    })
                } else {
                    if let Some(method) = f
                        .methods
                        .iter()
                        .find(|m| m.method_idx == (*method_idx as u16))
                    {
                        Some(Arc::new(Class::new(
                            "NONE".to_string(),
                            0,
                            f.get_type_name(method.class_idx)
                                .unwrap_or("NONE")
                                .to_string(),
                        )))
                    } else {
                        None
                    }
                }
            }
            Location::DexField(field_idx, f) => {
                if let Some(field) = f.fields.get((*field_idx) as usize) {
                    f.get_class_by_type(field.class_idx)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    pub fn get_dex_file(&self) -> Option<Arc<DexFile>> {
        match self {
            Location::Class(.., f)
            | Location::DexField(.., f)
            | Location::DexMethod(.., f)
            | Location::DexString(.., f)
            | Location::Type(.., f) => Some(f.clone()),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ConfidenceLevel {
    VeryLow,
    Low,
    Medium,
    High,
}

/*
let vals = vec![
        "method",
        "class",
        "types",
        "strings",
        "fields",
        "protos",
        "static_data",
    ]; */

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ObjectType {
    Method,
    Class,
    Type,
    String,
    Field,
    Proto,
    StaticData,
}
pub const ALL_TYPES: [ObjectType; 7] = [
    ObjectType::Method,
    ObjectType::Class,
    ObjectType::Type,
    ObjectType::String,
    ObjectType::Field,
    ObjectType::Proto,
    ObjectType::StaticData,
];

const CLASSES: [ObjectType; 2] = [ObjectType::Class, ObjectType::Type];

const METHODS: [ObjectType; 2] = [ObjectType::Method, ObjectType::Proto];

const FIELDS: [ObjectType; 1] = [ObjectType::Field];

pub fn find_string_matches(reg: &Regex, files: &Files) -> Vec<Evidence> {
    let mut matches = find_string_matches_in_dex_with_type(&reg, &ALL_TYPES, &files.multi_dex);
    matches.extend(find_string_matches_in_elf(&reg, &files.binaries));
    matches
}
pub fn find_classes(reg: &Regex, files: &Files) -> Vec<Evidence> {
    find_string_matches_in_dex_with_type(reg, &CLASSES, &files.multi_dex)
}

pub fn find_methods(reg: &Regex, files: &Files) -> Vec<Evidence> {
    find_string_matches_in_dex_with_type(reg, &METHODS, &files.multi_dex)
}
pub fn find_fields(reg: &Regex, files: &Files) -> Vec<Evidence> {
    find_string_matches_in_dex_with_type(reg, &FIELDS, &files.multi_dex)
}

pub fn find_any(reg: &Regex, object_types: &[ObjectType], files: &Files) -> Vec<Evidence> {
    find_string_matches_in_dex_with_type(reg, object_types, &files.multi_dex)
}

use regex::Regex;

use std::{
    sync::{Arc, Mutex},
    vec,
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::iter::{IndexedParallelIterator, ParallelIterator};

use coeus_macros::iterator;
use coeus_models::models::{AccessFlags, Class, DexFile, Field, Files, Method, MultiDexFile};

use super::{
    ConfidenceLevel, Context, CrossReferenceEvidence, Evidence, Location, ObjectType,
    StringEvidence,
};

pub fn get_native_methods(md: &MultiDexFile, _files: &Files) -> Vec<(Arc<DexFile>, Arc<Method>)> {
    let native_methods = iterator!(md.classes())
        .filter_map(|(f, m)| m.class_data.as_ref().map(|a| (f, a)))
        .flat_map(|(f, m)| {
            let direct = m
                .direct_methods
                .iter()
                .filter(|a| a.access_flags.contains(AccessFlags::NATIVE));
            let virt = m
                .virtual_methods
                .iter()
                .filter(|a| a.access_flags.contains(AccessFlags::NATIVE));
            direct
                .chain(virt)
                .map(|a| (f.clone(), f.methods[a.method_idx as usize].clone()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    //TODO: We probably also could try a simple guessing of which native library is loaded within this class by "decompiling" and checking for const arguments (or even try partial emulation for string decryption) to loadLibrary. For now leave it at what it is.
    return native_methods;
}

pub fn get_methods_for_type(the_type: &Context) -> Vec<Evidence> {
    match the_type {
        Context::DexClass(class, dex_file) => dex_file
            .get_methods_for_type(class.class_idx)
            .iter()
            .map(|md| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    context: the_type.clone(),
                    place: Location::DexMethod(md.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(md.clone(), dex_file.clone()),
                })
            })
            .collect(),
        Context::DexType(ty, _, dex_file) => dex_file
            .get_methods_for_type(*ty)
            .iter()
            .map(|md| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    context: the_type.clone(),
                    place: Location::DexMethod(md.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(md.clone(), dex_file.clone()),
                })
            })
            .collect(),
        _ => vec![],
    }
}
pub fn get_methods_for_type_owned(the_type: &Context, _files: &Files) -> Vec<Evidence> {
    let new_place: Context;
    match the_type {
        Context::DexClass(class, dex_file) => {
            new_place = Context::DexClass(class.clone(), dex_file.clone());
            dex_file
                .get_methods_for_type(class.class_idx)
                .iter()
                .map(|md| {
                    Evidence::CrossReference(CrossReferenceEvidence {
                        context: new_place.clone(),
                        place: Location::DexMethod(md.method_idx as u32, dex_file.clone()),
                        place_context: Context::DexMethod(md.clone(), dex_file.clone()),
                    })
                })
                .collect()
        }
        Context::DexType(ty, name, dex_file) => {
            new_place = Context::DexType(*ty, name.to_string(), dex_file.clone());
            dex_file
                .get_methods_for_type(*ty)
                .iter()
                .map(|md| {
                    Evidence::CrossReference(CrossReferenceEvidence {
                        context: new_place.clone(),
                        place: Location::DexMethod(md.method_idx as u32, dex_file.clone()),
                        place_context: Context::DexMethod(md.clone(), dex_file.clone()),
                    })
                })
                .collect()
        }
        _ => vec![],
    }
}

pub fn find_cross_reference(place: &Context, multi_dex: &MultiDexFile) -> Vec<Evidence> {
    match place {
        Context::DexClass(class, dex_file) => {
            find_references_to_class(class, dex_file.clone(), multi_dex, place)
        }
        Context::DexType(typ, _, dex_file) => {
            find_references_to_type(*typ, dex_file.clone(), multi_dex, place)
        }
        Context::DexMethod(method, dex_file) => {
            find_references_to_method(method, dex_file.clone(), multi_dex, place)
        }
        Context::DexField(field, dex_file) => {
            find_references_to_field(field, dex_file.clone(), multi_dex, place)
        }
        _ => vec![],
    }
}

pub fn find_cross_reference_array<'a: 'b, 'b>(
    places: &'b [Context],
    multi_dex: &'a Files,
) -> Vec<Evidence> {
    iterator!(places)
        .flat_map(|place| {
            let new_place: Context;
            match place {
                Context::DexClass(class, dex_file) => {
                    let (multi_dex, dex_file) = multi_dex
                        .get_multi_dex_from_dex_identifier(&dex_file.identifier)
                        .unwrap();
                    new_place = Context::DexClass(class.clone(), dex_file.clone());

                    find_references_to_class(&class, dex_file, multi_dex, &new_place)
                }
                Context::DexType(typ, name, dex_file) => {
                    let (multi_dex, dex_file) = multi_dex
                        .get_multi_dex_from_dex_identifier(&dex_file.identifier)
                        .unwrap();
                    new_place = Context::DexType(*typ, name.to_string(), dex_file.clone());

                    find_references_to_type(*typ, dex_file, multi_dex, &new_place)
                }
                Context::DexMethod(method, dex_file) => {
                    let (multi_dex, dex_file) = multi_dex
                        .get_multi_dex_from_dex_identifier(&dex_file.identifier)
                        .unwrap();
                    new_place = Context::DexMethod(method.clone(), dex_file.clone());

                    find_references_to_method(&method, dex_file, multi_dex, &new_place)
                }
                Context::DexField(field, dex_file) => {
                    let (multi_dex, dex_file) = multi_dex
                        .get_multi_dex_from_dex_identifier(&dex_file.identifier)
                        .unwrap();
                    new_place = Context::DexField(field.clone(), dex_file.clone());

                    find_references_to_field(&field, dex_file, multi_dex, &new_place)
                }
                Context::DexString(str_idx, dex_file) => {
                    let (multi_dex, dex_file) = multi_dex
                        .get_multi_dex_from_dex_identifier(&dex_file.identifier)
                        .unwrap();
                    new_place = Context::DexString(*str_idx, dex_file.clone());
                    find_references_to_string(*str_idx, dex_file, multi_dex, &new_place)
                }
                _ => vec![],
            }
        })
        .collect()
    // #[cfg(not(target_arch = "wasm32"))]
    // evidences.par_extend(result);
    // #[cfg(target_arch = "wasm32")]
    // evidences.extend(result);
    // evidences
}

fn find_references_to_string<'a: 'b, 'b>(
    str_idx: u32,
    dex_file: Arc<DexFile>,
    multi_dex: &'a MultiDexFile,
    place: &'b Context,
) -> Vec<Evidence> {
    let mut context_matches: Vec<Evidence> = vec![];
    let vec_loc = Arc::new(Mutex::new(&mut context_matches));
    let classes = multi_dex.classes();
    iterator!(classes).for_each(|(_f, c)| {
        let methods_containing_references: Vec<_> = iterator!(c.codes)
            .filter(|md| match md.code.as_ref() {
                Some(code) => {
                    let references =
                        iterator!(code.insns).filter(|(_, _, instruction)| match instruction {
                            coeus_models::models::Instruction::ConstString(_, str_ptr) => {
                                (*str_ptr as u32) == str_idx
                            }
                            coeus_models::models::Instruction::ConstStringJumbo(_, str_ptr) => {
                                *str_ptr == str_idx
                            }
                            _ => false,
                        });
                    references.count() > 0
                }
                _ => false,
            })
            .map(|m| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    place: Location::DexMethod(m.method.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(m.method.clone(), dex_file.clone()),
                    context: place.clone(),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_loc.lock() {
            lock.extend(methods_containing_references);
        }
    });
    context_matches
}

//TODO: refactor
fn find_references_to_type<'a: 'b, 'b>(
    typ: u32,
    dex_file: Arc<DexFile>,
    multi_dex: &'a MultiDexFile,
    place: &'b Context,
) -> Vec<Evidence> {
    let mut context_matches: Vec<Evidence> = vec![];
    let vec_loc = Arc::new(Mutex::new(&mut context_matches));

    let type_name = &dex_file.strings[typ as usize].to_str_lossy();

    let classes = multi_dex.classes();
    iterator!(classes).for_each(|(f, c)| {
        let methods_containing_references: Vec<_> = iterator!(c.codes)
            .filter(|md| match md.code.as_ref() {
                Some(code) => {
                    let references =
                        iterator!(code.insns)
                            .filter(|(_, _, instruction)| match instruction {
                                coeus_models::models::Instruction::Invoke(method_idx)
                                | coeus_models::models::Instruction::InvokeVirtual(
                                    _,
                                    method_idx,
                                    _,
                                )
                                | coeus_models::models::Instruction::InvokeSuper(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeDirect(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeStatic(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeInterface(
                                    _,
                                    method_idx,
                                    _,
                                ) => {
                                    if (*method_idx as usize) >= f.methods.len() {
                                        return false;
                                    }
                                    let method = &f.methods[*method_idx as usize];
                                    let name_idx = f.types[method.class_idx as usize];
                                    let name = &f.strings[name_idx as usize];
                                    if let Ok(name) = name.to_str() {
                                        return name == *type_name;
                                    }
                                    false
                                }

                                coeus_models::models::Instruction::NewInstance(_, type_idx) => {
                                    (*type_idx) == typ as u16
                                }

                                coeus_models::models::Instruction::StaticGet(_, field_id)
                                | coeus_models::models::Instruction::StaticGetWide(_, field_id)
                                | coeus_models::models::Instruction::StaticGetObject(_, field_id)
                                | coeus_models::models::Instruction::StaticGetBoolean(_, field_id)
                                | coeus_models::models::Instruction::StaticGetByte(_, field_id)
                                | coeus_models::models::Instruction::StaticGetChar(_, field_id)
                                | coeus_models::models::Instruction::StaticGetShort(_, field_id)
                                | coeus_models::models::Instruction::StaticPut(_, field_id)
                                | coeus_models::models::Instruction::StaticPutWide(_, field_id)
                                | coeus_models::models::Instruction::StaticPutObject(_, field_id)
                                | coeus_models::models::Instruction::StaticPutBoolean(_, field_id)
                                | coeus_models::models::Instruction::StaticPutByte(_, field_id)
                                | coeus_models::models::Instruction::StaticPutChar(_, field_id)
                                | coeus_models::models::Instruction::StaticPutShort(_, field_id)
                                | coeus_models::models::Instruction::InstanceGet(_, _, field_id)
                                | coeus_models::models::Instruction::InstanceGetWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetShort(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePut(_, _, field_id)
                                | coeus_models::models::Instruction::InstancePutWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutShort(
                                    _,
                                    _,
                                    field_id,
                                ) => match dex_file.fields.get((*field_id) as usize) {
                                    Some(field) => field.class_idx == typ as u16,
                                    _ => false,
                                },
                                _ => false,
                            });
                    references.count() > 0
                }
                None => false,
            })
            .map(|m| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    place: Location::DexMethod(m.method.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(m.method.clone(), dex_file.clone()),
                    context: place.clone(),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_loc.lock() {
            lock.extend(methods_containing_references);
        }
    });
    context_matches
}

fn find_references_to_field<'a: 'b, 'b>(
    field_idx: &'b Field,
    dex_file: Arc<DexFile>,
    _multi_dex: &'a MultiDexFile,
    place: &'b Context,
) -> Vec<Evidence> {
    let mut context_matches: Vec<Evidence> = vec![];
    let vec_loc = Arc::new(Mutex::new(&mut context_matches));
    let field_index = *iterator!(dex_file.fields)
        .enumerate()
        .filter_map(|(idx, f)| {
            if f.as_ref() == field_idx {
                Some(idx)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .first()
        .unwrap() as u16;
    iterator!(dex_file.classes).for_each(|c| {
        let methods_containing_references: Vec<_> = iterator!(c.codes)
            .filter(|md| match md.code.as_ref() {
                Some(code) => {
                    let references =
                            iterator!(code.insns).filter(|(_, _, instruction)| match instruction {
                                coeus_models::models::Instruction::StaticGet(_, field_id)
                                | coeus_models::models::Instruction::StaticGetWide(_, field_id)
                                | coeus_models::models::Instruction::StaticGetObject(_, field_id)
                                | coeus_models::models::Instruction::StaticGetBoolean(
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::StaticGetByte(_, field_id)
                                | coeus_models::models::Instruction::StaticGetChar(_, field_id)
                                | coeus_models::models::Instruction::StaticGetShort(_, field_id)
                                | coeus_models::models::Instruction::StaticPut(_, field_id)
                                | coeus_models::models::Instruction::StaticPutWide(_, field_id)
                                | coeus_models::models::Instruction::StaticPutObject(_, field_id)
                                | coeus_models::models::Instruction::StaticPutBoolean(
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::StaticPutByte(_, field_id)
                                | coeus_models::models::Instruction::StaticPutChar(_, field_id)
                                | coeus_models::models::Instruction::StaticPutShort(_, field_id)
                                | coeus_models::models::Instruction::InstanceGet(_, _, field_id)
                                | coeus_models::models::Instruction::InstanceGetWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetShort(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePut(_, _, field_id)
                                | coeus_models::models::Instruction::InstancePutWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutShort(
                                    _,
                                    _,
                                    field_id,
                                ) => *field_id == field_index,

                                _ => false,
                            });
                    references.count() > 0
                }
                None => false,
            })
            .map(|m| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    place: Location::DexMethod(m.method.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(m.method.clone(), dex_file.clone()),
                    context: place.clone(),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_loc.lock() {
            lock.extend(methods_containing_references);
        }
    });
    context_matches
}
fn find_references_to_method<'a: 'b, 'b>(
    looking_for_method_idx: &'b Method,
    dex_file: Arc<DexFile>,
    multi_dex: &'a MultiDexFile,
    place: &'b Context,
) -> Vec<Evidence> {
    let mut context_matches: Vec<Evidence> = vec![];
    let vec_loc = Arc::new(Mutex::new(&mut context_matches));
    let parent_method = dex_file
        .methods
        .get(looking_for_method_idx.method_idx as usize)
        .unwrap();
    let parent_class = dex_file
        .get_string(
            *dex_file
                .types
                .get(parent_method.class_idx as usize)
                .unwrap() as usize,
        )
        .unwrap();

    let classes = multi_dex.classes();
    iterator!(classes).for_each(|(f, c)| {
        let methods_containing_references: Vec<_> = iterator!(c.codes)
            .filter(|md| match md.code.as_ref() {
                Some(code) => {
                    let references =
                        iterator!(code.insns).filter(|(_, _, instruction)| match instruction {
                            coeus_models::models::Instruction::Invoke(method_idx)
                            | coeus_models::models::Instruction::InvokeVirtual(_, method_idx, _)
                            | coeus_models::models::Instruction::InvokeSuper(_, method_idx, _)
                            | coeus_models::models::Instruction::InvokeDirect(_, method_idx, _)
                            | coeus_models::models::Instruction::InvokeStatic(_, method_idx, _)
                            | coeus_models::models::Instruction::InvokeInterface(
                                _,
                                method_idx,
                                _,
                            ) => {
                                if let Some(this_method_name) = f.methods.get(*method_idx as usize)
                                {
                                    if this_method_name.method_name
                                        != looking_for_method_idx.method_name
                                    {
                                        return false;
                                    }
                                    let strings_index =
                                        f.types[this_method_name.class_idx as usize];
                                    if let Ok(the_class_name) =
                                        f.strings[strings_index as usize].to_str()
                                    {
                                        return the_class_name == parent_class;
                                    }
                                }
                                false
                            }

                            _ => false,
                        });
                    references.count() > 0
                }
                None => false,
            })
            .map(|m| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    place: Location::DexMethod(m.method.method_idx as u32, f.clone()),
                    place_context: Context::DexMethod(m.method.clone(), f.clone()),
                    context: place.clone(),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_loc.lock() {
            lock.extend(methods_containing_references);
        }
    });
    context_matches
}

fn find_references_to_class<'a: 'b, 'b>(
    class_idx: &'b Class,
    dex_file: Arc<DexFile>,
    multi_dex: &'a MultiDexFile,
    place: &'b Context,
) -> Vec<Evidence> {
    let mut context_matches: Vec<Evidence> = vec![];
    let vec_loc = Arc::new(Mutex::new(&mut context_matches));
    let classes = multi_dex.classes();
    iterator!(classes).for_each(|(f, c)| {
        let methods_containing_references: Vec<_> = iterator!(c.codes)
            .filter(|md| match md.code.as_ref() {
                Some(code) => {
                    let references =
                        iterator!(code.insns)
                            .filter(|(_, _, instruction)| match instruction {
                                coeus_models::models::Instruction::Invoke(method_idx)
                                | coeus_models::models::Instruction::InvokeVirtual(
                                    _,
                                    method_idx,
                                    _,
                                )
                                | coeus_models::models::Instruction::InvokeSuper(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeDirect(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeStatic(_, method_idx, _)
                                | coeus_models::models::Instruction::InvokeInterface(
                                    _,
                                    method_idx,
                                    _,
                                ) => {
                                    if *method_idx == 0xffff {
                                        return false;
                                    }
                                    let method = &f.methods[*method_idx as usize];
                                    let name_idx = f.types[method.class_idx as usize];
                                    let name = &f.strings[name_idx as usize];
                                    if let Ok(name) = name.to_str() {
                                        return name == class_idx.class_name;
                                    }
                                    false
                                }

                                coeus_models::models::Instruction::NewInstance(_, type_idx) => {
                                    (*type_idx) == class_idx.class_idx as u16
                                }

                                coeus_models::models::Instruction::StaticGet(_, field_id)
                                | coeus_models::models::Instruction::StaticGetWide(_, field_id)
                                | coeus_models::models::Instruction::StaticGetObject(_, field_id)
                                | coeus_models::models::Instruction::StaticGetBoolean(_, field_id)
                                | coeus_models::models::Instruction::StaticGetByte(_, field_id)
                                | coeus_models::models::Instruction::StaticGetChar(_, field_id)
                                | coeus_models::models::Instruction::StaticGetShort(_, field_id)
                                | coeus_models::models::Instruction::StaticPut(_, field_id)
                                | coeus_models::models::Instruction::StaticPutWide(_, field_id)
                                | coeus_models::models::Instruction::StaticPutObject(_, field_id)
                                | coeus_models::models::Instruction::StaticPutBoolean(_, field_id)
                                | coeus_models::models::Instruction::StaticPutByte(_, field_id)
                                | coeus_models::models::Instruction::StaticPutChar(_, field_id)
                                | coeus_models::models::Instruction::StaticPutShort(_, field_id)
                                | coeus_models::models::Instruction::InstanceGet(_, _, field_id)
                                | coeus_models::models::Instruction::InstanceGetWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstanceGetShort(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePut(_, _, field_id)
                                | coeus_models::models::Instruction::InstancePutWide(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutObject(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutBoolean(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutByte(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutChar(
                                    _,
                                    _,
                                    field_id,
                                )
                                | coeus_models::models::Instruction::InstancePutShort(
                                    _,
                                    _,
                                    field_id,
                                ) => match dex_file.fields.get((*field_id) as usize) {
                                    Some(field) => field.class_idx == class_idx.class_idx as u16,
                                    _ => false,
                                },
                                _ => false,
                            });
                    references.count() > 0
                }
                None => false,
            })
            .map(|m| {
                Evidence::CrossReference(CrossReferenceEvidence {
                    place: Location::DexMethod(m.method.method_idx as u32, dex_file.clone()),
                    place_context: Context::DexMethod(m.method.clone(), dex_file.clone()),
                    context: place.clone(),
                })
            })
            .collect();
        if let Ok(mut lock) = vec_loc.lock() {
            lock.extend(methods_containing_references);
        }
    });
    context_matches
}

pub fn find_string_matches_for_method_name(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let methods = dex.methods();
        let method_matches: Vec<_> = iterator!(methods)
            .enumerate()
            .filter(|(_, (_, m))| reg.is_match(&m.method_name))
            .map(|(_, (dex, m))| {
                Evidence::String(StringEvidence {
                    content: m.method_name.clone(),
                    place: Location::DexMethod(m.method_idx as u32, dex.clone()),
                    context: Context::DexMethod(m.clone(), dex.clone()),
                    confidence_level: ConfidenceLevel::Medium,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(method_matches);
        }
    });
    matches
}

pub fn find_string_matches_for_class_name(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let classes = dex.classes();
        let class_matches: Vec<_> = iterator!(classes)
            .filter(|(_, c)| reg.is_match(&c.class_name))
            .map(|(dex, c)| {
                Evidence::String(StringEvidence {
                    content: c.class_name.to_string(),
                    place: Location::Class(c.class_idx, dex.clone()),
                    context: Context::DexClass(c.clone(), dex.clone()),
                    confidence_level: ConfidenceLevel::Medium,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(class_matches);
        }
    });
    matches
}

pub fn find_string_matches_for_type_name(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let types = dex.types();
        let type_matches: Vec<Evidence> = iterator!(types)
            .filter(
                |type_idx| match (**type_idx).0.strings.get(((**type_idx).1) as usize) {
                    Some(name) => reg.is_match(&name.to_str_lossy()),
                    None => false,
                },
            )
            .map(|type_idx| {
                let type_name = (*type_idx)
                    .0
                    .strings
                    .get(((*type_idx).1) as usize)
                    .unwrap()
                    .to_str()
                    .unwrap();

                Evidence::String(StringEvidence {
                    content: type_name.to_owned(),
                    place: Location::Type((*type_idx).1, (*type_idx).0.clone()),
                    context: Context::DexType(
                        (*type_idx).1,
                        type_name.to_string(),
                        (*type_idx).0.clone(),
                    ),
                    confidence_level: ConfidenceLevel::Medium,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(type_matches);
        }
    });
    matches
}

pub fn find_string_matches_for_field_name(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let fields = dex.fields();
        let field_matches: Vec<_> = iterator!(fields)
            .enumerate()
            .filter(|(_, (dex, m))| match dex.get_string(m.name_idx as usize) {
                Some(matched) => reg.is_match(matched),
                None => false,
            })
            .map(|(i, (dex, m))| {
                Evidence::String(StringEvidence {
                    content: dex.get_string(m.name_idx as usize).unwrap().to_owned(),
                    place: Location::DexField(i as u32, dex.clone()),
                    context: Context::DexField(m.clone(), dex.clone()),
                    confidence_level: ConfidenceLevel::Medium,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(field_matches);
        }
    });
    matches
}
use std::convert::TryInto;

pub fn find_string_matches_for_static_data(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let classes = dex.classes();
        let field_matches: Vec<_> = iterator!(classes)
            .enumerate()
            .map(|(i, (dex, m))| {
                let static_data = iterator!(m.static_fields)
                    .enumerate()
                    .filter_map(|(index, s)| {
                        let index = m.class_data.as_ref().unwrap().static_fields[index].field_idx;
                        match s.value_type {
                            coeus_models::models::ValueType::Byte => None,
                            coeus_models::models::ValueType::String => {
                                if let Some(string) = dex.get_string(s.get_string_id() as usize) {
                                    if reg.is_match(string) {
                                        Some((index, string.to_string()))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            coeus_models::models::ValueType::Array => {
                                let array = s.inner.as_ref().unwrap();
                                let inner_bytes: Vec<u8> = array.try_into().unwrap_or_default();
                                let string = String::from_utf8_lossy(&inner_bytes);
                                if reg.is_match(&string) {
                                    Some((index, string.to_string()))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>();
                (i, (dex, m, static_data))
            })
            .flat_map(|(i, (dex, _, static_data))| {
                iterator!(static_data)
                    .map(|(e, s)| {
                        Evidence::String(StringEvidence {
                            content: s.clone(),
                            place: Location::Class(i as u32, dex.clone()),
                            context: Context::DexStaticField(
                                dex.fields[*e as usize].clone(),
                                dex.clone(),
                            ),
                            confidence_level: ConfidenceLevel::High,
                        })
                    })
                    .collect::<Vec<Evidence>>()
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(field_matches);
        }
    });
    matches
}

pub fn find_string_matches_for_proto(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let protos = dex.protos();
        let proto_matches: Vec<Evidence> = iterator!(protos)
            .enumerate()
            .filter(
                |(_, (dex, proto))| match dex.get_string(proto.shorty_idx as usize) {
                    Some(shorty) => reg.is_match(shorty),
                    _ => false,
                },
            )
            .map(|(i, s)| {
                Evidence::String(StringEvidence {
                    content: s.0.get_string(s.1.shorty_idx as usize).unwrap().to_string(),
                    place: Location::DexMethod(i as u32, s.0.clone()),
                    context: Context::DexProto(s.1.clone(), s.0.clone()),
                    confidence_level: ConfidenceLevel::Medium,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(proto_matches);
        }
    });
    matches
}

pub fn find_string_matches_for_string_entries(
    reg: &Regex,
    files: &[MultiDexFile],
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));
    iterator!(files).for_each(|dex| {
        let strings = dex.strings();
        let string_matches: Vec<Evidence> = iterator!(strings)
            .enumerate()
            .filter(|(_, s)| match s.1.to_str() {
                Ok(r) => reg.is_match(r),
                _ => false,
            })
            .map(|(i, s)| {
                Evidence::String(StringEvidence {
                    content: s.1.to_str().unwrap().to_string(),
                    place: Location::DexString(i as u32, s.0.clone()),
                    context: Context::DexString(i as u32, s.0.clone()),
                    confidence_level: ConfidenceLevel::VeryLow,
                })
            })
            .collect();
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(string_matches);
        }
    });
    matches
}

pub fn find_string_matches_in_dex(reg: &Regex, files: &[MultiDexFile]) -> Vec<Evidence> {
    find_string_matches_in_dex_with_type(reg, &super::ALL_TYPES, files)
}

pub fn find_string_matches_in_dex_with_type(
    reg: &Regex,
    object_types: &[ObjectType],
    files: &[MultiDexFile],
) -> Vec<Evidence> {
    let mut matches = vec![];
    let vec_lock = Arc::new(Mutex::new(&mut matches));

    iterator!(object_types).for_each(|search_op| {
        let matches = match *search_op {
            ObjectType::Method => find_string_matches_for_method_name(reg, files),
            ObjectType::Class => find_string_matches_for_class_name(reg, files),
            ObjectType::Type => find_string_matches_for_type_name(reg, files),
            ObjectType::String => find_string_matches_for_string_entries(reg, files),
            ObjectType::Field => find_string_matches_for_field_name(reg, files),
            ObjectType::Proto => find_string_matches_for_proto(reg, files),
            ObjectType::StaticData => find_string_matches_for_static_data(reg, files),
        };
        if let Ok(mut lock) = vec_lock.lock() {
            lock.extend(matches);
        }
    });
    matches
}

pub fn get_class_for_evidence(evidence: &Evidence) -> Option<Arc<Class>> {
    match evidence {
        Evidence::String(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c),
            Location::Type(t, f) => f.get_class_by_type_name_idx(*t),
            Location::DexMethod(m, f) => {
                if let Some(method) = f.get_method_by_idx(*m) {
                    f.get_class_by_type(method.method.class_idx)
                } else {
                    None
                }
            }

            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::Instructions(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c),
            Location::Type(t, f) => f.get_class_by_type_name_idx(*t),
            Location::DexMethod(m, f) => {
                if let Some(method) = f.get_method_by_idx(*m) {
                    f.get_class_by_type(method.method.class_idx)
                } else {
                    None
                }
            }
            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::CrossReference(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c),
            Location::Type(t, f) => f.get_class_by_type_name_idx(*t),
            Location::DexMethod(m, f) => {
                if let Some(method) = f.get_method_by_idx(*m) {
                    f.get_class_by_type(method.method.class_idx)
                } else {
                    None
                }
            }
            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::BytePattern(_) => None,
    }
}

pub fn get_class_for_owned_evidence(evidence: &Evidence) -> Option<(Arc<Class>, Arc<DexFile>)> {
    match evidence {
        Evidence::String(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c).map(|c| (c, f.to_owned())),
            Location::Type(t, f) => Some((
                Arc::new(Class::new(
                    f.identifier.clone(),
                    *iterator!(f.types)
                        .enumerate()
                        .filter_map(|(_index, ty)| if ty == t { Some(*ty) } else { None })
                        .collect::<Vec<_>>()
                        .first()
                        .unwrap() as u32,
                    f.get_string(*t as usize).unwrap().to_string(),
                )),
                f.to_owned(),
            )),
            Location::DexMethod(m, f) => {
                if let Some(method) = f.get_method_by_idx(*m) {
                    f.get_class_by_type(method.method.class_idx)
                        .map(|c| (c, f.to_owned()))
                } else {
                    None
                }
            }
            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                        .map(|c| (c, file.to_owned()))
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::Instructions(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c).map(|c| (c, f.to_owned())),
            Location::Type(t, f) => Some((
                Arc::new(Class::new(
                    f.identifier.clone(),
                    *iterator!(f.types)
                        .enumerate()
                        .filter_map(|(index, ty)| if ty == t { Some(index) } else { None })
                        .collect::<Vec<_>>()
                        .first()
                        .unwrap() as u32,
                    f.get_string(*t as usize).unwrap().to_string(),
                )),
                f.to_owned(),
            )),
            Location::DexMethod(m, f) => {
                let file = f.clone();

                if let Some(method) = file.get_method_by_idx(*m) {
                    file.get_class_by_type(method.method.class_idx)
                        .map(|c| (c, f.clone()))
                } else {
                    None
                }
            }
            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                        .map(|c| (c, file.to_owned()))
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::CrossReference(se) => match &se.place {
            Location::DexString(_, _) => None,
            Location::Class(c, f) => f.get_class_by_type(*c).map(|c| (c, f.to_owned())),
            Location::Type(t, f) => Some((
                Arc::new(Class::new(
                    f.identifier.clone(),
                    *iterator!(f.types)
                        .enumerate()
                        .filter_map(|(index, ty)| if ty == t { Some(index) } else { None })
                        .collect::<Vec<_>>()
                        .first()
                        .unwrap() as u32,
                    f.get_string(*t as usize).unwrap().to_string(),
                )),
                f.to_owned(),
            )),
            Location::DexMethod(m, f) => {
                if let Some(method) = f.get_method_by_idx(*m) {
                    f.get_class_by_type(method.method.class_idx)
                        .map(|c| (c, f.to_owned()))
                } else {
                    None
                }
            }
            Location::DexField(f, file) => {
                if let Some(field) = file.fields.get(*f as usize) {
                    file.get_class_by_type(field.class_idx)
                        .map(|c| (c, file.to_owned()))
                } else {
                    None
                }
            }
            _ => None,
        },
        Evidence::BytePattern(_) => None,
    }
}

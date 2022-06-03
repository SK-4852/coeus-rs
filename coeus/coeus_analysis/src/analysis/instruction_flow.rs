// Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    collections::HashMap,
    ops::{Add, BitAnd, BitOr, BitXor, Mul, Rem, Shl, Shr, Sub},
    sync::Arc,
};

use coeus_models::models::{
    Class, CodeItem, DexFile, Instruction, InstructionOffset, InstructionSize, Method,
};
use coeus_parse::coeus_emulation::vm::{
    runtime::StringClass, ClassInstance, Register, VMException, VM,
};

#[derive(Clone, Debug)]
pub struct InstructionFlow {
    branches: Vec<Branch>,
    method: HashMap<InstructionOffset, (InstructionSize, Instruction)>,
    dex: Arc<DexFile>,
    register_size: u16,
    already_branched: Vec<InstructionOffset>,
    conservative: bool,
}
#[derive(Clone, Debug)]
pub struct Branch {
    pub id: u64,
    pub pc: InstructionOffset,
    pub state: State,
}
impl Default for Branch {
    fn default() -> Self {
        Self {
            id: rand::random(),
            pc: InstructionOffset(0),
            state: Default::default(),
        }
    }
}
impl PartialEq for Branch {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
#[derive(Clone, Debug)]
pub struct State {
    pub id: u64,
    pub registers: Vec<Value>,
    pub last_instruction: Option<LastInstruction>,
}
impl Default for State {
    fn default() -> Self {
        let id: u64 = rand::random();
        Self {
            id,
            registers: Default::default(),
            last_instruction: Default::default(),
        }
    }
}

#[derive(Clone)]
pub enum LastInstruction {
    FunctionCall {
        name: String,
        signature: String,
        class_name: String,
        class: Arc<Class>,
        method: Arc<Method>,
        args: Vec<Value>,
        result: Option<Value>,
    },
    ReadField {
        name: String,
    },
    StoreField {
        name: String,
        arg: Value,
    },
    BinaryOperation {
        left: Value,
        right: Value,
        operation: fn(&Value, &Value) -> Value,
    },
}

impl LastInstruction {
    pub fn execute(&mut self, vm: &mut VM) -> Result<Value, VMException> {
        match self {
            LastInstruction::FunctionCall {
                name: _name,
                signature: _signature,
                class_name,
                class,
                method,
                args,
                result,
            } => {
                let evaluated_args = args
                    .into_iter()
                    .filter_map(|a| a.try_get_value(vm).ok())
                    .filter(|a| !matches!(a, Value::Unknown { .. } | Value::Empty))
                    .collect::<Vec<_>>();
                if evaluated_args.len() != args.len() {
                    return Err(VMException::LinkerError);
                }
                let mut vm_args = vec![];
                for arg in evaluated_args {
                    let arg = match arg {
                        Value::String(n) => {
                            let string_class = StringClass::new(n);
                            vm.new_instance(
                                StringClass::class_name().to_string(),
                                coeus_parse::coeus_emulation::vm::Value::Object(string_class),
                            )
                            .unwrap_or(Register::Null)
                        }
                        Value::Boolean(b) => Register::Literal(if b { 1 } else { 0 }),
                        Value::Number(n) => Register::Literal(n as i32),
                        Value::Char(n) => Register::Literal(n as i32),
                        Value::Byte(n) => Register::Literal(n as i32),
                        Value::Bytes(bytes) => vm
                            .new_instance(
                                "[B".to_string(),
                                coeus_parse::coeus_emulation::vm::Value::Array(bytes),
                            )
                            .unwrap_or(Register::Null),
                        Value::Variable(_f) => {
                            unreachable!("We evaluated before")
                        }
                        Value::Unknown { ty } | Value::Object { ty } => vm
                            .new_instance(
                                ty,
                                coeus_parse::coeus_emulation::vm::Value::Object(
                                    ClassInstance::new(class.clone()),
                                ),
                            )
                            .unwrap_or(Register::Null),

                        Value::Invalid => Register::Null,
                        Value::Empty => Register::Empty,
                    };
                    vm_args.push(arg);
                }
                if let Ok((file, function)) = vm.lookup_method(class_name, &method) {
                    let function = function.clone();
                    if let Some(code) = &function.code {
                        vm.start(
                            method.method_idx as u32,
                            &file.get_identifier(),
                            code,
                            vm_args,
                        )?;
                    } else {
                        vm.invoke_runtime(file.clone(), method.method_idx as u32, vm_args)?;
                    };
                } else {
                    vm.invoke_runtime_with_method(class_name, method.clone(), vm_args)?;
                }

                let r = vm
                    .get_return_object()
                    .map(|a| match a {
                        coeus_parse::coeus_emulation::vm::Value::Array(a) => Value::Bytes(a),
                        coeus_parse::coeus_emulation::vm::Value::Object(o) => {
                            if &o.class.class_name == StringClass::class_name() {
                                Value::String(format!("{}", o))
                            } else {
                                Value::Object {
                                    ty: o.class.class_name.to_string(),
                                }
                            }
                        }
                        coeus_parse::coeus_emulation::vm::Value::Int(i) => {
                            if let Some(Value::Object { ty }) = result {
                                if ty == "Z" {
                                    Value::Boolean(i == 1)
                                } else {
                                    Value::Number(i as i128)
                                }
                            } else {
                                Value::Number(i as i128)
                            }
                        }
                        coeus_parse::coeus_emulation::vm::Value::Short(s) => {
                            Value::Number(s as i128)
                        }
                        coeus_parse::coeus_emulation::vm::Value::Byte(b) => Value::Byte(b as u8),
                    })
                    .unwrap_or(Value::Invalid);
                *result = Some(r.clone());
                Ok(r)
            }
            LastInstruction::BinaryOperation {
                left,
                right,
                operation,
            } => {
                let left = left.try_get_value(vm)?;
                let right = right.try_get_value(vm)?;
                let result = operation(&left, &right);
                Ok(result)
            }
            _ => Err(VMException::LinkerError),
        }
    }
}

impl std::fmt::Debug for LastInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionCall {
                name,
                signature,
                method: _method,
                class_name: _class_name,
                class: _class,
                args,
                result,
            } => f
                .debug_struct("FunctionCall")
                .field("name", name)
                .field("signature", signature)
                .field("args", args)
                .field("result", result)
                .finish(),
            Self::ReadField { name } => f.debug_struct("ReadField").field("name", name).finish(),
            Self::StoreField { name, arg } => f
                .debug_struct("StoreField")
                .field("name", name)
                .field("arg", arg)
                .finish(),
            Self::BinaryOperation {
                left,
                right,
                operation: _operation,
            } => f
                .debug_struct("BinaryOperation")
                .field("left", left)
                .field("right", right)
                .finish(),
        }
    }
}
#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Number(i128),
    Boolean(bool),
    Char(char),
    Byte(u8),
    Bytes(Vec<u8>),
    Variable(Box<LastInstruction>),
    Unknown { ty: String },
    Object { ty: String },
    Invalid,
    Empty,
}

impl Value {
    pub fn try_get_number(&self) -> Option<i128> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Byte(b) => Some(*b as i128),
            Self::Char(c) => Some(*c as i128),
            Self::Boolean(b) => Some(if *b { 1 } else { 0 }),
            _ => None,
        }
    }
    pub fn try_get_value(&mut self, vm: &mut VM) -> Result<Value, VMException> {
        if let Value::Variable(instruction) = self {
            instruction.execute(vm)
        } else {
            Ok(self.clone())
        }
    }
    pub fn is_constant(&self) -> bool {
        !matches!(
            self,
            Value::Variable(..)
                | Value::Unknown { .. }
                | Value::Object { .. }
                | Value::Invalid
                | Value::Empty
        )
    }
}

impl<'a> BitXor for &'a Value {
    type Output = Value;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left ^ right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs ^ rhs)
    }
}
impl<'a> BitXor<i128> for &'a Value {
    type Output = Value;

    fn bitxor(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left ^ right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs ^ rhs)
    }
}
impl<'a> BitAnd for &'a Value {
    type Output = Value;

    fn bitand(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs & rhs)
    }
}
impl<'a> BitAnd<i128> for &'a Value {
    type Output = Value;

    fn bitand(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left & right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs & rhs)
    }
}
impl<'a> BitOr for &'a Value {
    type Output = Value;

    fn bitor(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs | rhs)
    }
}
impl<'a> BitOr<i128> for &'a Value {
    type Output = Value;

    fn bitor(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left | right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs | rhs)
    }
}
impl<'a> Rem for &'a Value {
    type Output = Value;

    fn rem(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        if rhs == 0 {
            return Value::Invalid;
        }
        Value::Number(lhs % rhs)
    }
}
impl<'a> Rem<i128> for &'a Value {
    type Output = Value;

    fn rem(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left % right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs % rhs)
    }
}
impl<'a> Add for &'a Value {
    type Output = Value;
    fn add(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs + rhs)
    }
}
impl<'a> Add<i128> for &'a Value {
    type Output = Value;

    fn add(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left + right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs + rhs)
    }
}
impl<'a> Sub for &'a Value {
    type Output = Value;

    fn sub(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs - rhs)
    }
}
impl<'a> Sub<i128> for &'a Value {
    type Output = Value;

    fn sub(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left - right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs - rhs)
    }
}
impl<'a> Mul for &'a Value {
    type Output = Value;

    fn mul(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs * rhs)
    }
}
impl<'a> Mul<i128> for &'a Value {
    type Output = Value;

    fn mul(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left * right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs * rhs)
    }
}
impl<'a> Shl for &'a Value {
    type Output = Value;

    fn shl(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(rhs, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs << rhs)
    }
}
impl<'a> Shl<i128> for &'a Value {
    type Output = Value;

    fn shl(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left << right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs << rhs)
    }
}
impl<'a> Shr for &'a Value {
    type Output = Value;

    fn shr(self, rhs: Self) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        let rhs = if let Some(n) = rhs.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: rhs.clone(),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs >> rhs)
    }
}
impl<'a> Shr<i128> for &'a Value {
    type Output = Value;

    fn shr(self, rhs: i128) -> Self::Output {
        let lhs = if let Some(n) = self.try_get_number() {
            n
        } else if matches!(self, Value::Variable { .. }) {
            return Value::Variable(Box::new(LastInstruction::BinaryOperation {
                left: self.clone(),
                right: Value::Number(rhs),
                operation: |left, right| left >> right,
            }));
        } else {
            return Value::Invalid;
        };
        Value::Number(lhs >> rhs)
    }
}

const MAX_ITERATIONS: usize = 1_000;
impl InstructionFlow {
    pub fn get_instruction(
        &self,
        offset: &InstructionOffset,
    ) -> Option<(InstructionSize, Instruction)> {
        self.method.get(offset).map(|a| a.clone())
    }
    pub fn new(method: CodeItem, dex: Arc<DexFile>) -> Self {
        let register_size = method.register_size;
        let method: HashMap<_, _> = method
            .insns
            .into_iter()
            .map(|(size, offset, instruction)| (offset, (size, instruction)))
            .collect();

        Self {
            branches: vec![],
            method,
            dex,
            register_size,
            already_branched: vec![],
            conservative: true,
        }
    }

    pub fn get_all_branch_decisions(&mut self) -> Vec<Branch> {
        if self.branches.is_empty() {
            self.new_branch(InstructionOffset(0));
        }
        let mut branches = vec![];
        let mut iterations = 0;
        loop {
            self.next_instruction();
            for b in &self.branches {
                let instruction = if let Some(instruction) = self.method.get(&b.pc) {
                    instruction
                } else {
                    continue;
                };
                if matches!(
                    instruction.1,
                    Instruction::Test(..) | Instruction::TestZero(..)
                ) {
                    branches.push(b.clone());
                }
            }
            if self.is_done() {
                break;
            }
            if iterations > MAX_ITERATIONS {
                break;
            }
            iterations += 1;
        }
        branches
    }

    pub fn find_all_calls(&mut self, signature: &str) -> Vec<Branch> {
        let mut branches = vec![];
        let mut iterations = 0;
        self.new_branch(InstructionOffset(0));
        loop {
            self.next_instruction();
            for state in self.get_all_states() {
                match &state.last_instruction {
                    Some(LastInstruction::FunctionCall {
                        name: _name,
                        signature: sig,
                        class_name: _class_name,
                        method: _method,
                        class: _class,
                        args: _args,
                        result: _result,
                    }) if sig == signature => {
                        if let Some(b) = self.branches.iter().find(|a| a.state.id == state.id) {
                            branches.push(b.clone());
                        }
                    }

                    _ => {}
                }
            }
            if self.is_done() {
                return branches;
            }
            if iterations > MAX_ITERATIONS {
                return branches;
            }
            iterations += 1;
        }
    }
    pub fn next_instruction(&mut self) {
        let mut branches_to_add: Vec<Branch> = vec![];
        let mut branches_to_remove: Vec<u64> = vec![];
        for b in &mut self.branches {
            let instruction = if let Some(instruction) = self.method.get(&b.pc) {
                instruction
            } else {
                branches_to_remove.push(b.id);
                continue;
            };

            match instruction.1 {
                // Flow Control
                Instruction::Goto8(offset) => {
                    b.pc += offset as i32;
                    continue;
                }
                Instruction::Goto16(offset) => {
                    b.pc += offset as i32;
                    continue;
                }
                Instruction::Goto32(offset) => {
                    b.pc += offset as i32;
                    continue;
                }

                Instruction::Test(test, left, right, offset) => {
                    if self.already_branched.contains(&b.pc) {
                        continue;
                    }
                    if let (Some(left), Some(right)) = (
                        b.state.registers[u8::from(left) as usize].try_get_number(),
                        b.state.registers[u8::from(right) as usize].try_get_number(),
                    ) {
                        log::warn!("DEAD BRANCH");
                        let jump_to_offset = match test {
                            coeus_models::models::TestFunction::Equal => left == right,
                            coeus_models::models::TestFunction::NotEqual => left != right,
                            coeus_models::models::TestFunction::LessThan => left < right,
                            coeus_models::models::TestFunction::LessEqual => left <= right,
                            coeus_models::models::TestFunction::GreaterThan => left > right,
                            coeus_models::models::TestFunction::GreaterEqual => left >= right,
                        };
                        if jump_to_offset {
                            b.pc += offset as i32;
                        }
                        continue;
                    } else {
                        let mut new_branch = b.clone();
                        new_branch.pc += offset as i32;
                        branches_to_add.push(new_branch);
                        self.already_branched.push(b.pc);
                    }
                }
                Instruction::TestZero(test, left, offset) => {
                    if self.already_branched.contains(&b.pc) {
                        continue;
                    }
                    if let Some(left) = b.state.registers[u8::from(left) as usize].try_get_number()
                    {
                        log::warn!("DEAD BRANCH");
                        let jump_to_offset = match test {
                            coeus_models::models::TestFunction::Equal => left == 0,
                            coeus_models::models::TestFunction::NotEqual => left != 0,
                            coeus_models::models::TestFunction::LessThan => left < 0,
                            coeus_models::models::TestFunction::LessEqual => left <= 0,
                            coeus_models::models::TestFunction::GreaterThan => left > 0,
                            coeus_models::models::TestFunction::GreaterEqual => left >= 0,
                        };
                        if jump_to_offset {
                            b.pc += offset as i32;
                        }
                        continue;
                    }
                    let mut new_branch = b.clone();
                    new_branch.pc += offset as i32;
                    branches_to_add.push(new_branch);
                    self.already_branched.push(b.pc);
                }
                Instruction::Switch(_, table_offset) => {
                    if let Some((_, Instruction::SwitchData(switch))) =
                        self.method.get(&(b.pc + table_offset))
                    {
                        for (_, offset) in &switch.targets {
                            if self.already_branched.contains(&b.pc) {
                                continue;
                            }
                            let mut new_branch = b.clone();
                            new_branch.pc += *offset as i32;
                            branches_to_add.push(new_branch);
                        }
                    }
                    branches_to_remove.push(b.id);
                    continue;
                }

                //basic arithmetic
                Instruction::XorInt(left, right) | Instruction::XorLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        ^ &b.state.registers[u8::from(right) as usize]
                }
                Instruction::XorIntDst(dst, left, right)
                | Instruction::XorLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        ^ &b.state.registers[u8::from(right) as usize]
                }
                Instruction::XorIntDstLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] ^ (lit as i128)
                }
                Instruction::XorIntDstLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] ^ (lit as i128)
                }
                Instruction::RemIntDst(dst, left, right)
                | Instruction::RemLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        % &b.state.registers[u8::from(right) as usize]
                }
                Instruction::RemInt(left, right) | Instruction::RemLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        % &b.state.registers[u8::from(right) as usize]
                }
                Instruction::RemIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] % (lit as i128)
                }
                Instruction::RemIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] % (lit as i128)
                }

                Instruction::AddInt(left, right) | Instruction::AddLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        + &b.state.registers[u8::from(right) as usize]
                }
                Instruction::AddIntDst(dst, left, right)
                | Instruction::AddLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        + &b.state.registers[u8::from(right) as usize]
                }
                Instruction::AddIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] + (lit as i128)
                }
                Instruction::AddIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] + (lit as i128)
                }

                Instruction::SubInt(left, right) | Instruction::SubLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        - &b.state.registers[u8::from(right) as usize]
                }
                Instruction::SubIntDst(dst, left, right)
                | Instruction::SubLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        - &b.state.registers[u8::from(right) as usize]
                }
                Instruction::SubIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] - (lit as i128)
                }
                Instruction::SubIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] - (lit as i128)
                }

                Instruction::MulInt(left, right) | Instruction::MulLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        * &b.state.registers[u8::from(right) as usize]
                }
                Instruction::MulIntDst(dst, left, right)
                | Instruction::MulLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        * &b.state.registers[u8::from(right) as usize]
                }
                Instruction::MulIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] * (lit as i128)
                }
                Instruction::MulIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] * (lit as i128)
                }

                Instruction::AndInt(left, right) | Instruction::AndLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        & &b.state.registers[u8::from(right) as usize]
                }
                Instruction::AndLongDst(dst, left, right)
                | Instruction::AndIntDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        & &b.state.registers[u8::from(right) as usize]
                }
                Instruction::AndIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] & (lit as i128)
                }
                Instruction::AndIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] & (lit as i128)
                }

                Instruction::OrInt(left, right) | Instruction::OrLong(left, right) => {
                    b.state.registers[u8::from(left) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        | &b.state.registers[u8::from(right) as usize]
                }
                Instruction::OrIntDst(dst, left, right)
                | Instruction::OrLongDst(dst, left, right) => {
                    b.state.registers[u8::from(dst) as usize] = &b.state.registers
                        [u8::from(left) as usize]
                        | &b.state.registers[u8::from(right) as usize]
                }
                Instruction::OrIntLit8(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] | (lit as i128)
                }
                Instruction::OrIntLit16(dst, left, lit) => {
                    b.state.registers[u8::from(dst) as usize] =
                        &b.state.registers[u8::from(left) as usize] | (lit as i128)
                }

                // invocations
                Instruction::Invoke(_) => {}
                Instruction::InvokeType(_) => {}

                Instruction::InvokeVirtual(_, method, ref regs)
                | Instruction::InvokeSuper(_, method, ref regs)
                | Instruction::InvokeDirect(_, method, ref regs)
                | Instruction::InvokeStatic(_, method, ref regs)
                | Instruction::InvokeInterface(_, method, ref regs) => {
                    let m = &self.dex.methods[method as usize];
                    let proto = &self.dex.protos[m.proto_idx as usize];

                    let sig = proto.to_string(&self.dex);
                    let return_type = proto.get_return_type(&self.dex);
                    let class_name = self.dex.get_type_name(m.class_idx).unwrap_or_default();
                    let class = self
                        .dex
                        .get_class_by_type_name_idx(m.class_idx)
                        .unwrap_or(Arc::new(Class {
                            class_name: class_name.to_string(),
                            class_idx: m.class_idx as u32,
                            ..Default::default()
                        }))
                        .clone();
                    let args = regs
                        .iter()
                        .map(|a| b.state.registers[*a as usize].clone())
                        .collect::<Vec<_>>();
                    let function_call = LastInstruction::FunctionCall {
                        name: m.method_name.clone(),
                        method: m.clone(),
                        class_name: class_name.to_string(),
                        class,
                        signature: format!("{}->{}{}", class_name, m.method_name, sig),
                        args,
                        result: if return_type == "V" {
                            None
                        } else {
                            Some(Value::Object { ty: return_type })
                        },
                    };
                    b.state.last_instruction = Some(function_call);
                }

                Instruction::InvokeVirtualRange(_, method, _)
                | Instruction::InvokeSuperRange(_, method, _)
                | Instruction::InvokeDirectRange(_, method, _)
                | Instruction::InvokeStaticRange(_, method, _)
                | Instruction::InvokeInterfaceRange(_, method, _) => {
                    let m = &self.dex.methods[method as usize];
                    let proto = &self.dex.protos[m.proto_idx as usize];
                    let sig = proto.to_string(&self.dex);
                    let return_type = proto.get_return_type(&self.dex);
                    let class_name = self.dex.get_type_name(m.class_idx).unwrap_or_default();
                    let class = self
                        .dex
                        .get_class_by_type_name_idx(m.class_idx)
                        .unwrap_or(Arc::new(Class {
                            class_name: class_name.to_string(),
                            class_idx: m.class_idx as u32,
                            ..Default::default()
                        }))
                        .clone();
                    let args = vec![];
                    let function_call = LastInstruction::FunctionCall {
                        name: m.method_name.clone(),
                        method: m.clone(),
                        class_name: class_name.to_string(),
                        class,
                        signature: format!("{}->{}{}", class_name, m.method_name, sig),
                        args,
                        result: if return_type == "V" {
                            None
                        } else {
                            Some(Value::Object { ty: return_type })
                        },
                    };
                    b.state.last_instruction = Some(function_call);
                }

                // const
                Instruction::ConstLit4(reg, val) => {
                    b.state.registers[u8::from(reg) as usize] = Value::Number(u8::from(val) as i128)
                }
                Instruction::ConstLit16(reg, val) => {
                    b.state.registers[reg as usize] = Value::Number(val as i128)
                }
                Instruction::ConstLit32(reg, val) => {
                    b.state.registers[reg as usize] = Value::Number(val as i128)
                }

                Instruction::ConstString(reg, str_idx) => {
                    b.state.registers[reg as usize] = self
                        .dex
                        .get_string(str_idx)
                        .map(|a| Value::String(a.to_string()))
                        .unwrap_or(Value::Unknown {
                            ty: String::from("Ljava/lang/String;"),
                        });
                }
                Instruction::ConstStringJumbo(reg, str_idx) => {
                    b.state.registers[reg as usize] = self
                        .dex
                        .get_string(str_idx as usize)
                        .map(|a| Value::String(a.to_string()))
                        .unwrap_or(Value::Unknown {
                            ty: String::from("Ljava/lang/String;"),
                        })
                }
                Instruction::ConstClass(reg, c) => {
                    let class_name = self
                        .dex
                        .get_class_name(c)
                        .map(|a| Value::Unknown { ty: a.to_string() })
                        .unwrap_or(Value::Unknown {
                            ty: String::from("TYPE NOT FOUND"),
                        });
                    b.state.registers[reg as usize] = class_name;
                }
                Instruction::Const => {}
                Instruction::ConstWide => {}

                // casts
                Instruction::IntToByte(dst, src) => {
                    if let Value::Number(numb) = b.state.registers[u8::from(src) as usize] {
                        b.state.registers[u8::from(dst) as usize] = Value::Byte(numb as u8);
                    }
                }
                Instruction::IntToChar(dst, src) => {
                    if let Value::Number(numb) = b.state.registers[u8::from(src) as usize] {
                        b.state.registers[u8::from(dst) as usize] = Value::Char(numb as u8 as char);
                    }
                }

                // new instances and arrays
                Instruction::ArrayLength(dst, array) => {
                    if let Value::Bytes(ref v) = b.state.registers[u8::from(array) as usize] {
                        b.state.registers[u8::from(dst) as usize] = Value::Number(v.len() as i128);
                    } else {
                        b.state.registers[u8::from(dst) as usize] = Value::Invalid;
                    }
                }
                Instruction::NewInstance(reg, ty) => {
                    if let Some(type_name) = self.dex.get_type_name(ty) {
                        b.state.registers[reg as usize] = Value::Object {
                            ty: type_name.to_string(),
                        };
                    } else {
                        b.state.registers[reg as usize] = Value::Unknown {
                            ty: format!("UNKNOWN"),
                        };
                    }
                }
                Instruction::NewInstanceType(_) => {}
                Instruction::NewArray(_, _, _) => {}
                Instruction::FilledNewArray(_, _, _) => {}
                Instruction::FilledNewArrayRange(_, _, _) => {}
                Instruction::FillArrayData(_, _) => {}
                Instruction::ArrayGetByte(dst, arr_reg, index_reg) => {
                    if let (Value::Bytes(a), Value::Number(index)) = (
                        &b.state.registers[arr_reg as usize],
                        &b.state.registers[index_reg as usize],
                    ) {
                        b.state.registers[dst as usize] = Value::Byte(a[*index as usize]);
                    } else {
                        b.state.registers[dst as usize] = Value::Empty;
                    }
                }
                Instruction::ArrayPutByte(src, arr_reg, index_reg) => {
                    let index = if let Value::Number(n) = b.state.registers[index_reg as usize] {
                        Some(n)
                    } else {
                        None
                    };
                    let byte = if let Value::Byte(b) = &b.state.registers[src as usize] {
                        Some(*b)
                    } else {
                        None
                    };
                    if let (Value::Bytes(a), Some(index)) =
                        (&mut b.state.registers[arr_reg as usize], index)
                    {
                        if let Some(b) = byte {
                            a[index as usize] = b;
                        }
                    }
                }
                Instruction::ArrayGetChar(dst, arr_reg, index_reg) => {
                    if let (Value::Bytes(a), Value::Number(index)) = (
                        &b.state.registers[arr_reg as usize],
                        &b.state.registers[index_reg as usize],
                    ) {
                        b.state.registers[dst as usize] = Value::Char(a[*index as usize] as char);
                    } else {
                        b.state.registers[dst as usize] = Value::Empty;
                    }
                }
                Instruction::ArrayPutChar(src, arr_reg, index_reg) => {
                    let index = if let Value::Number(n) = b.state.registers[index_reg as usize] {
                        Some(n)
                    } else {
                        None
                    };
                    let byte = if let Value::Char(b) = &b.state.registers[src as usize] {
                        Some(*b)
                    } else {
                        None
                    };
                    if let (Value::Bytes(a), Some(index)) =
                        (&mut b.state.registers[arr_reg as usize], index)
                    {
                        if let Some(b) = byte {
                            a[index as usize] = b as u8;
                        }
                    }
                }

                // FieldAccess
                Instruction::StaticGet(dst, _)
                | Instruction::StaticGetObject(dst, _)
                | Instruction::StaticGetBoolean(dst, _)
                | Instruction::StaticGetByte(dst, _)
                | Instruction::StaticGetChar(dst, _)
                | Instruction::StaticGetShort(dst, _) => {
                    let dst: u8 = (dst).into();
                    b.state.registers[dst as usize] = Value::Empty;
                }
                Instruction::StaticGetWide(dst, _) => {
                    let dst: u8 = (dst).into();
                    b.state.registers[dst as usize] = Value::Empty;
                    b.state.registers[dst as usize + 1] = Value::Empty;
                }
                Instruction::StaticPut(_, _) => {}
                Instruction::StaticPutWide(_, _) => {}
                Instruction::StaticPutObject(_, _) => {}
                Instruction::StaticPutBoolean(_, _) => {}
                Instruction::StaticPutByte(_, _) => {}
                Instruction::StaticPutChar(_, _) => {}
                Instruction::StaticPutShort(_, _) => {}

                Instruction::InstanceGet(dst, _, _)
                | Instruction::InstanceGetObject(dst, _, _)
                | Instruction::InstanceGetShort(dst, _, _)
                | Instruction::InstanceGetBoolean(dst, _, _)
                | Instruction::InstanceGetByte(dst, _, _)
                | Instruction::InstanceGetChar(dst, _, _) => {
                    let dst: u8 = (dst).into();
                    b.state.registers[dst as usize] = Value::Empty;
                }
                Instruction::InstanceGetWide(dst, ..) => {
                    let dst: u8 = (dst).into();
                    b.state.registers[dst as usize] = Value::Empty;
                    b.state.registers[dst as usize + 1] = Value::Empty;
                }

                Instruction::InstancePut(_, _, _) => {}
                Instruction::InstancePutWide(_, _, _) => {}
                Instruction::InstancePutObject(_, _, _) => {}
                Instruction::InstancePutBoolean(_, _, _) => {}
                Instruction::InstancePutByte(_, _, _) => {}
                Instruction::InstancePutChar(_, _, _) => {}
                Instruction::InstancePutShort(_, _, _) => {}

                // moves
                Instruction::Move(dst, src) | Instruction::MoveObject(dst, src) => {
                    let dst: u8 = (dst).into();
                    let src: u8 = (src).into();
                    b.state.registers[dst as usize] = b.state.registers[src as usize].clone();
                }
                Instruction::Move16(dst, src) | Instruction::MoveObject16(dst, src) => {
                    b.state.registers[dst as usize] = b.state.registers[src as usize].clone();
                }

                Instruction::MoveResult(reg)
                | Instruction::MoveResultWide(reg)
                | Instruction::MoveResultObject(reg) => {
                    if let Some(function_call) = &b.state.last_instruction {
                        b.state.registers[reg as usize] =
                            Value::Variable(Box::new(function_call.clone()));
                    }
                }

                // branch finished
                // we also use this for unhandled instructions
                Instruction::ReturnVoid
                | Instruction::Return(..)
                | Instruction::Throw(..)
                | Instruction::MoveFrom16(..)
                | Instruction::MoveWide(..)
                | Instruction::MoveWideFrom16(..)
                | Instruction::MoveWide16(..)
                | Instruction::MoveObjectFrom16(..) => {
                    branches_to_remove.push(b.id);
                    continue;
                }
                // We don't need those
                Instruction::NotImpl(_, _) => {
                    if self.conservative {
                        for reg in &mut b.state.registers {
                            *reg = Value::Empty;
                        }
                    }
                }
                Instruction::ArrayData(_, _) => {}
                Instruction::SwitchData(_) => {}
                Instruction::Nop => {}
            }
            // reset last_function if this is not a function call
            if !is_function_call(&instruction.1)
                && matches!(
                    b.state.last_instruction,
                    Some(LastInstruction::FunctionCall { .. })
                )
            {
                b.state.last_instruction = None;
            }
            b.pc += instruction.0 .0 / 2;
        }
        self.branches
            .retain(|a| !branches_to_remove.iter().any(|id| &a.id == id));
        if self.branches.len() < 1000 {
            for b in branches_to_add {
                self.fork(b);
            }
        }
    }
    fn new_branch(&mut self, pc: InstructionOffset) {
        self.branches.push(Branch {
            id: rand::random(),
            pc,
            state: State {
                id: rand::random(),
                registers: vec![Value::Empty; self.register_size as usize],
                last_instruction: None,
            },
        });
    }
    fn fork(&mut self, mut branch: Branch) {
        branch.id = rand::random();
        branch.state.id = rand::random();
        self.branches.push(branch);
    }
    pub fn is_done(&self) -> bool {
        self.branches.is_empty()
    }
    pub fn get_all_states(&self) -> Vec<&State> {
        self.branches.iter().map(|b| &b.state).collect()
    }
}

fn is_function_call(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Invoke(..)
            | Instruction::InvokeDirect(..)
            | Instruction::InvokeDirectRange(..)
            | Instruction::InvokeInterface(..)
            | Instruction::InvokeInterfaceRange(..)
            | Instruction::InvokeStatic(..)
            | Instruction::InvokeStaticRange(..)
            | Instruction::InvokeSuper(..)
            | Instruction::InvokeSuperRange(..)
            | Instruction::InvokeVirtual(..)
            | Instruction::InvokeVirtualRange(..)
    )
}

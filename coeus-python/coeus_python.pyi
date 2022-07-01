# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


from typing import Any, Optional

class Branching:
    def has_dead_branch(self) -> bool: ...
    def branch_offset(self) -> Optional[int]: ...
    def get_method(self) -> Method: ...
class Manifest:
    def get_xml(self) -> str:
        """Return the content of the AndroidManifest as found in the APK"""
    def get_json(self) -> str:
        """If the XML could be parsed as an object, return the corresponding JSON representation"""
class Runtime:
    pass
class DexVm:
    def __init__(self, ao: AnalyzeObject): ...
    def get_current_state(self) -> str:
        """Get a string representation of the current machine state."""
    def get_heap(self) -> str:
        """Get a string representation of the heap."""
    def get_instances(self) -> str:
        """Return a string representation of all instances"""
    def get_static_field(self, fqdn: str) -> VmResult:
        """Try get a static field already defined on the VM"""
    
class VmResult:
    def get_value(self) -> Any:
        """"Cast the VmResult to a python native type"""
class DexClassObject:
    pass
class DexString:
    def content(self) -> str:
        """Return the content of this String"""
class NativeSymbol:
    def symbol(self) -> str:
        """The name of the symbol as found in the dynamic_strtable"""
    def is_export(self) -> bool: ...
    def address(self) -> int:
        """Return the file offset of the symbol. This offset is from the start of the file."""
    def get_function_bytes(self) -> bytes:
        """Return the bytes to the symbol. Currently only works for (exported) functions. Use e.g. capstone to disassemble the bytes."""

class FieldAccess:
    """A helper class for field access"""
    def get_instruction(self) -> str:
        """Get the opcode of the instruction"""
    def get_field(self) -> DexField:
        """Get a backreference to the DexField"""
    def get_class(self) -> Class:
        """Get the class where the field access came from"""
    def get_function(self) -> Method:
        """Get the method where the field access was found"""
class DexField:
    def try_get_value(self, dex_vm: DexVm) -> VmResult:
        """Try evaluating the static dex context to find values set for this field. This only accurately works for static final fields, as they (should) are not accessed anymore."""
    def field_name(self) -> str:
        """Return the name of this field"""
    def fqdn(self) -> str:
        """Get the full qualified domain name, uniquely identifying this field."""
    def get_class(self) -> Class:
        """Return the class this field was defined on."""
    def get_field_access(self, ao: AnalyzeObject) -> list[FieldAccess]:
        """Get a list instructions accessing this field"""
    dex_class : Class
    """The class this field is defined on."""
class Evidence:
    def cross_references(self, ao: AnalyzeObject) -> list[Evidence]:
        """Find cross references to this object. Currently, this only works for dex objects."""
    def downcast(self) -> Any:
        """Downcast the evidence to a concrete type. This raises a `RuntimeException` if the evidence cannot be cast to a known, mapped type."""
    def as_method(self) -> Method:
        """Interpret this `Evidence` as a `Method`. Raises a `RuntimeException` if it cannot be cast."""
    def as_class(self) -> Class:
        """Interpret this `Evidence` as a `Class`. Raises a `RuntimeException` if it cannot be cast."""
    def as_string(self) -> DexString:
        """Interpret this `Evidence` as a `String`. Raises a `RuntimeException` if it cannot be cast."""
    def as_field(self) -> DexField:
        """Interpret this `Evidence` as a `Field`. Raises a `RuntimeException` if it cannot be cast."""
    def as_native_symbol(self) -> NativeSymbol:
        """Interpret this `Evidence` as a `NativeSymbol`. Raises a `RuntimeException` if it cannot be cast."""
class Instruction:
    def get_arguments_as_value(self) -> list[Any]:
        """Return all arguments as python values, if they are constant"""
    def get_string_arguments(self) -> list[str]:
        """Return all arguments to this functions that are constant strings."""
    def get_argument_types(self) -> list[str]:
        """Return the type names of all arguments. If the argument was a result of a previous function call, it prints the debug string of the inner arguments."""
    def execute(self, vm: DexVm) -> Any:
        """Try executing the instruction with the VM. This can help evaluate possible `const` functions or simple static string encryptors"""
class Method:
    def name(self) -> str:
        """"Return the name of this function."""
    def signature(self) -> str:
        """Return the fully qualified domain name inclusive the signature. This should uniquely identify the function within the dex context."""
    def proto_type(self) -> str:
        """Return the prototype string for this method."""
    def code(self) -> str:
        """Return a best effort disassembly of this method."""
    def get_class(self) -> Class:
        """Get the class this method is defined on."""
    def __call__(self, *args: Any, **kwds: Any) -> VmResult:
        """Prepare a virtual machine and run the function, returning the result the function returned."""
    def cross_references(self, ao: AnalyzeObject) -> list[Evidence]:
        """Find all methods, referencing this method."""
    def find_method_call(self, signature: str) -> list[Instruction]:
        """Statically analyse this function to look for a specifica method call. It performs basic register flow analysis and returns the possible arguments for the specified method."""
    def get_argument_types_string(self) -> list[str]:
        """Get a list of all argument types. This can be used as a helper function e.g. to build Frida scripts"""
    def get_return_type(self) -> str:
        """Get this methods return type"""
    def find_all_branch_decisions(self, vm: DexVm) -> list[Branching]:
        """Return a list of all branch decisions and their branch registers. Can be used to perform some dead branch analysis for example. Currently, this is still experimental."""
    @staticmethod
    def find_all_branch_decisions_array(methods: list[Method], vm:DexVm) -> list[Branching]:
        """"Same as `find_all_branch_decisions` but acting on an array of methods to use `rayon` for parallelization. Currently, this is non satisfactory as we have to clone the VM for each call (or lock the mutex)"""
    
class Class:
    def name(self) -> str:
        """Returns the class name as used internally"""
    def code(self, ao: AnalyzeObject) -> str:
        """Return a best effort disassembly of the class"""
    def find_method_call(self, signature: str) -> list[Instruction]:
        """Try to find a method in this class, matching the specified signature."""
    def get_methods(self) -> list[Method]:
        """Get all methods found on this class"""
    def get_method(self, name: str) -> Method:
        """Get a method of this class by name"""
    def __getitem__(self, name: str) -> Method:
        """Get a method of this class by name"""
    def friendly_name(self) -> str:
        """Get a `friendly` name for this class."""

class AnalyzeObject:
    # atest#
    def __init__(self, file_name: str, build_graph: bool, max_nesting: int):
        """Initialize a analysis session. Currently, build_graph does not do much.
         `max_nesting` specifies how deep the recursion should go to look for libraries and 
         resources.
        """
    def get_runtime(self, method: Method) -> Runtime:
        """Get the runtime of dex files needed to run emulation."""
    def get_native_methods(self) -> list[Method]:
        """Get a list of all methods in the APK, which are marked `native`"""
    def find_methods(self, regex: str) -> list[Evidence]:
        """Look for methods matching the specified regex"""
    def find_fields(self, regex: str) -> list[Evidence]:
         """Look for fields matching the specified regex"""
    def find_strings(self, regex: str) -> list[Evidence]:
         """Look for strings matching the specified regex"""
    def find_classes(self, regex: str) -> list[Evidence]:
         """Look for classes matching the specified regex"""
    def get_classes(self) -> list(Evidence):
        """Retrun all classes"""
    def get_strings(self) -> list(Evidence):
        """Retrun all strings"""
    def get_methods(self) -> list(Evidence):
        """Retrun all methods"""
    def get_fields(self) -> list(Evidence):
        """Retrun all fields"""        
    def find_native_imports(self, file: str, pattern: str) -> list[Evidence]:
         """Check the dynamic_string table of the elf binary to look for imported functions"""
    def find_native_exports(self, file: str, pattern: str) -> list[Evidence]:
        """Check the dynamic_string table of the elf binary to look for exported functions (e.g. functions which are used from java)"""
    def find_native_strings(self, file: str, pattern: str) -> list[Evidence]:
        """This function currently does not do much"""
    def find(self, regex: str) -> list[Evidence]:
        """Try matching the regex for any type of object in the Dex context"""
    def get_manifests(self) -> list[Manifest]:
        """Get all found manifests."""
    def __getitem__(self, name) -> list[tuple[str, bytes]]:
        """Access the resource specified by `name`"""
    def find_dynamically_registered_functions(self, regex: str, libName: str) -> list[Evidence]:
        """Find dynamically registered functions in `libName`, matching the name given by `regex`."""
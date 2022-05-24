# Coeus-Python

Coeus-Python is the python interface to interact with the `coeus` library. It uses `pyo3` to expose `coeus` API to python.

## Build

To build the native module (aka wheel) we need [maturin](https://github.com/PyO3/maturin). With `maturin` installed it is as simple as `maturin build --release`. This should build the rust crate and the python API yielding a wheel in the `target/wheels` directory. The wheel can then be installed with pip with something similar to `python -m pip install --force-reinstall <path-to-wheel>.whl`.

## Type Hints
Coeus-Python includes type hints, which should provide enough information for IDEs to provide type checking and auto completion. If the API is adjusted, the `coeus_python.pyi` file should be updated to reflect the changes in the API.

## Entry Point

To start an analysis with coeus-python, one always starts of with the `AnalyzeObject`. This object provides functions to load and parse an APK, as well as search throught the APK.

## Native Support

Currently, most of the analysis is done on the dex part of the APK (aka. Java). There is the possibility to search for imported/exported functions in native libraries. Further, there is experimental support to search for strings in the `.rodata` section of the ELF binary. 

## Emulation

In order to get and analyse certain static (heap allocated) fields the static constructor of a class needs to be run. This is demonstrated in the following code sample:

```python
from coeus_python import AnalyzeObject, DexVm;

# Parse and load the APK
ao = AnalyzeObject("test.apk", True, 0);

# Find the interesting field
# in this case we already know what we are looking for:
# Lch/admin/bag/covidcertificate/sdk/android/SdkEnvironment;->PROD

fields = ao.find_fields("^PROD$")
# here we should be more rigorous, but since we basically find references to the field and 
# the fields definition we have to check multiple locations
field = fields[1].as_field()

# We also know in which class the field is defined... 
SdkEnviornment = ao.find_classes("SdkEnvironment")[0].as_class()

# ... and that it is a static class with heap allocated static fields, hence has a <clinit>
class_initializer = field.dex_class["<clinit>"]
# Now we construct a VM based on the resources found in the AnalyzeObject
vm = DexVm(ao)
# The library overides __call__, which means we can conveniently just call the methods
# If there were any arguments we could also supply the arguments. Primitive types should
# be automatically converted. For complex types it is a bit more involved
# as we need to provide a pointer to the object in the VMs HEAP
class_initializer(vm=vm)
print(field.fqdn())
# Now we can just access the static field based on the fully qualified domain name.
# The Value is indexable, and returns fields on the class.
print(vm.get_static_field(field.fqdn()).get_value()["trustListBaseUrl"])
```
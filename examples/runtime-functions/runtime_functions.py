# Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject, UnsafeRegister, UnsafeContext, DexVm, DynamicPythonClass

# We define the SuperClass here
class SuperClass:
    def __init__(self, theArgument):
        self.theArgument = theArgument
    # The rust function will call functions on SuperClass with the UnsafeContext set 
    # (from which we get access to the VM heap and such)
    def getArgument(self, context: UnsafeContext):
        # We construct a new string
        result = UnsafeRegister(self.theArgument, context)
        # and set it as the return value (see the signature in SuperClass.java)
        context.set_result(result)
    def print(self, context: UnsafeContext):
        # get all arguments
        args = context.get_arguments()
        # and convert the VM object to a python object
        theStringArg = context.get_value(args[0])
        # print the value
        print(theStringArg)

ao = AnalyzeObject("classes.dex", True, -1)
# Find the method from the Test class
doPrint = ao.find_methods("doPrint")[0].as_method()
# Construct a VM object
vm = DexVm(ao)
# Register our Python class in the VM. Each time we invoke-static a function of superclass
# the function is proxied to our python class
vm.register_class(DynamicPythonClass("Lch/ubique/SuperClass;", SuperClass("Hello from Python")))

# invoke the java VM class, which invokes our Python-Code 
doPrint()
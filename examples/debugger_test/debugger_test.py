# Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject, Debugger, StackValue, VmInstance

# Open the apk and parse it
ao = AnalyzeObject("./app-debug.apk", True, -1)
# Find the relevant class...
fragment_class = ao.find_classes("Lcom/example/biometricprompttest/FirstFragment;")[0]
# ... and function
onAuthSuccess = fragment_class.as_class()["onAuthSuccess"]
# Start a debugger instance, using the forwarded port 8000 to connect to the jdwp process on the device
debugger = Debugger("localhost", 8000)
print(onAuthSuccess.get_class().name())
print(onAuthSuccess.signature())
# We set a breakpoint for code_inde 5. This is just after push the "test" string into register 0.
debugger.set_breakpoint(onAuthSuccess, 5)
# Now to our badly implemented event loop
while True:
    try:
        # we just wait for any package from the device. If a breakpoint is hit, we should get a composite event
        frame = debugger.wait_for_package()
        # we disassemble the instructions and...
        code = onAuthSuccess.code()
        # ... show an arrow to the instruction we currently are
        code = code.replace(
            f"#0x{frame.get_code_index():x}", f"#0x{frame.get_code_index():x} <======="
        )
        print(code)
        print()
        print("###############")

        # we also print the current top level stackframe
        while True:
            print()
            print("StackFrame")
            print()
            # since android OS does not give us access to the information about locals, we need to extract
            # the number of registers in use from the function meta data.
            values = frame.get_values_for(debugger, onAuthSuccess)
            i = 0
            for val in values:
                # this will lookup string values
                # For object references it will lookup the class name
                # this class name should be in the correct format to be used for
                # furhter analysis with coeus (keep in mind the regex escaping)
                v = val.get_value(debugger)
                if isinstance(v, VmInstance):
                    print(f"v{i}: {v.to_string(debugger)}")
                else:
                    print(f"v{i}: {v}")
                i += 1
            print()
            cmd = input("Command? ")
            cmd_parts = cmd.split(" ")
            # c for continue
            if cmd_parts[0] == "c":
                debugger.resume()
                break
            elif cmd_parts[0] == "step":
                frame.step(debugger)
                debugger.resume()
                break
            # The set command needs a register and a value
            # We try to be somewhat smart about infering the correct register type, by also looking at the old value
            # (essentially needed for the size of integers or float values, since python does not differentiate between double, float, int, long,byte and so on)
            # set 0 test
            elif cmd_parts[0] == "set":
                register = int(cmd_parts[1])
                oldRegister = values[register]
                intValue = None
                floatValue = None
                try:
                    intValue = int(cmd_parts[2])
                except:
                    pass
                try:
                    floatValue = float(cmd_parts[2])
                except:
                    pass
                if intValue:
                    newRegister = StackValue(debugger, intValue, oldRegister)
                elif floatValue:
                    newRegister = StackValue(debugger, intValue, oldRegister)
                else:
                    newRegister = StackValue(debugger, cmd_parts[2], oldRegister)
                # Now we can issue the set command on this frame for the chosen register
                frame.set_value(debugger, register, newRegister)
            # q for quit
            elif cmd_parts[0] == "q":
                debugger.resume()
                break
    except Exception as e:
        print(e)
        pass

# Copyright (c) 2022 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from coeus_python import AnalyzeObject
import sys

# Extract the APK and parse the dex files

# This APK has proguard activated, and causes the BouncyCastle provider to be obfuscated
ao = AnalyzeObject("test-proguard.apk", False, -1)

# Here on the other hand we have proguard completely deactivated, and we can find the algorithm providers
# ao = AnalyzeObject("test-noproguard.apk", False, -1)

# Here we have proguard activated, but have an exception rule for BouncyCastle
# ao = AnalyzeObject("test-proguard-bc-exception.apk", False, -1)

# Let's find the methods for Security.addProvider... 
addProvider = ao.find_methods("addProvider")
# ... from which we can find the actual call sites
crossReferences = addProvider[0].cross_references(ao)
# Use static flow analysis to find the argument for the addProvider method
usageInstruction = (
    crossReferences[0]
    .as_method().find_method_call("Ljava/security/Security;\->addProvider\(Ljava/security/Provider;\)I")[0]
)
# The only argument to the addProvider method is the actual provider we want to add
getBouncyCastleProvider = usageInstruction.get_argument_types()[0]

# Now we can lookup the actual provider, and get the class definition of it
bcs = ao.find_classes(getBouncyCastleProvider.replace("/", "."))
foundBcClass = False

# we just wan't to check every occurences, since we might have some classes defined in dex classes, without an actual 
# definition
for b in bcs:
    # we were looking for classes, so this should be safe
    bc = b.as_class()
    print("Checking ", bc.name())
    # now do the static flow analysis again, to try to find the string arguments to the 
    # put method, which is used to actually register certain algorithms/providers
    
    # this is the interface function we are looking for. This one is usually used, when 
    # proguard obfuscated and minimized the binary
    putCalls = bc.find_method_call(
        "Ljava/security/Provider;\->put\(Ljava/lang/Object;Ljava/lang/Object;\)Ljava/lang/Object;"
    )
    
    # It might be that the provider provides an override, or the function is not obfuscated
    # in which case we call the virtual function
    putBcCalls = bc.find_method_call(
        bc.name() + "\->put\(Ljava/lang/Object;Ljava/lang/Object;\)Ljava/lang/Object;"
    )
    if len(putCalls) > 0:
        for pbc in putCalls:
            # now we just iterate through any invocation and hope 
            # that one actually uses const-strings. Otherwise
            # we'd have to perform further analysis
            stringArgs = pbc.get_string_arguments()
            if len(stringArgs) > 1:
                someProviderClass = stringArgs[1]
                # a neat side effect of using regex is
                # that we can leave the Java-Code way of writing
                # classes with a `.`. Here we just replace it with
                # the Java VM case of `/` to be more explicit
                someProviderLookup = ao.find_classes(
                    someProviderClass.replace(".", "/")
                )
                if len(someProviderLookup) > 0:
                    foundBcClass = True
                    break
    if len(putBcCalls) > 0:
        for pbc in putBcCalls:
            # and we do the same for the non-obfuscated case, just to 
            # make sure, that the providers are actually in the dexfile
            stringArgs = pbc.get_string_arguments()
            if len(stringArgs) > 1:
                someProviderClass = stringArgs[1]
                # a neat side effect of using regex is
                # that we can leave the Java-Code way of writing
                # classes with a `.`. Here we just replace it with
                # the Java VM case of `/` to be more explicit.
                someProviderLookup = ao.find_classes(someProviderClass.replace(".", "/"))
                if len(someProviderLookup) > 0:
                    foundBcClass = True
                    break
if foundBcClass:
    print("We found the BC classes")
else:
    print("Proguard rule needed for BC")
    sys.exit(1)

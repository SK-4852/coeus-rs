#!/bin/sh

javac --release 11  Test.java ch/ubique/SuperClass.java
d8 Test.class
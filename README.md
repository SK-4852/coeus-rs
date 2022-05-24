# Coeus

## What is Coeus

Coeus is a framework to analyse mobile applications.
Currently its main focuse is on Android APKs, but there are plans to expand native code analysis.

Coeus is composed of various different sub-crates to make it as modular as possible.
Coeus exposes a [rhai](https://rhai.rs/) interface which has quite some abstractions, but is considered deprecated.
Currently the plan is to improve the Python interface, as it offers much more possibilities into further analysis, as, e.g. combining Coeus with the excellent [Capstone](https://www.capstone-engine.org/) disassembler.

## How to use it

The easiest way to play around with Coeus is to use the [coeus-python](./coeus-python) module, and look at the examples.
For build instructions check out the [Readme](./coeus-python/README.md) in the coues-python module.

Next to the `coeus-python` module there is also a Rhai interface, which could be used, though usage is deprecated. To actually build the Rhai interface, use the feature-flag `rhai`.

Coeus can also be used as a crate in another Rust application. Just add it as a dependency to your project and start using it ;).

See the [examples](examples) directory for a simple tutorial and some example usage scenarios of Coeus.

## What can Coeus do?

Coeus offers the following features:

- Extract APKs and other zip-like archives
- Parse all Dex files found
- Parse all Native-Object-Files (thanks to [goblin](https://docs.rs/goblin/0.5.1/goblin/))
- Provide methods to search for objects within the dex-file
- Provide a Dex-Emulator for simple Code execution
- Build a Graph of an Application and provide Callgraphs and such (thanks to [petgraph](https://docs.rs/petgraph/latest/petgraph/))
- Provide Information-Flow-Analysis for static function evaluation

## Contributions

Please feel free to open PRs and contribute to Coeus.
# Downloads

[← Back to Main Documentation](index.md)

The Nomicle programs are written in Python and have been successfully tested on Windows, macOS, and Linux. The Nomicle C library is currently an Xcode project that only builds on macOS. However, with a simple makefile, you can probably get it to build on Linux or Windows.

The Nomicle programs are made available under a GPL-2.0 license while the Nomicle development libraries are available under the more permissive MIT license.

## Prerequisites

Nomicle has a few dependencies that you need to install on your system before you can get it to run:

- The Fortifier, Seeder, and Block Explorer require:
  - [Python 3](https://www.python.org/download/releases/3.0/)
  - The [cryptography](https://cryptography.io/en/latest/) Python package
- `libcnomicle` requires:
  - A C compiler
  - The [OpenSSL C library](https://www.openssl.org)

## Download Options

### Complete Bundles

- **[The Complete Bundle (Windows)](release/bundle_win_0.1.zip)**
  - Contains the Fortifier (`fort.py`) + Seeder (`seed.py`) + `PyNomicle`
  - Includes a shell script to start the system as background processes
  - Note: No Windows script currently exists for stopping the programs (contributions welcome)

- **[The Complete Bundle (macOS/Linux)](release/bundle_unix_0.1.zip)**
  - Contains the Fortifier (`fort.py`) + Seeder (`seed.py`) + `PyNomicle`
  - Includes two shell scripts to start/stop the system as background processes

### Individual Components

- **[Fortifier](https://github.com/alimahouk/nomicle/blob/master/fort.py)**
  - This program generates new Nomicle identity blocks and fortifies them

- **[Seeder](https://github.com/alimahouk/nomicle/blob/master/seed.py)**
  - This program seeds your identity block to other computers and fetches the identities of others for apps on your system to use

- **[Block Explorer](https://github.com/alimahouk/nomicle/blob/master/explorer.py)**
  - Invoke this script with the path to a Nomicle identity block file to print out the details of that block
  - Requires the `PyNomicle` library
  - [Guide to using the Block Explorer](explorer.md)

## For App Developers

### Libraries

- **[PyNomicle](https://github.com/alimahouk/nomicle/tree/master/PyNomicle)**
  - Download and import `nomicle` into your Python project to access Nomicle data structures

- **[libcnomicle](https://github.com/alimahouk/nomicle/tree/master/libcnomicle)**
  - The Nomicle C library
  - Requires OpenSSL development headers

You'll find the [developer documentation](developer/) to be a valuable resource.

## Additional Resources

- [Browse the entire code repository](https://github.com/alimahouk/nomicle)
- [Read the guide](tutorial.md) to help you get started after downloading the programs

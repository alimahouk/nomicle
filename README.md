# Nomicle

A self-sovereign identity system that enables decentralized identity management and verification.

## Overview

Nomicle is a peer-to-peer identity system that allows users to create, manage, and verify digital identities in a decentralized manner. The system uses cryptographic principles to ensure the security and authenticity of identity blocks.

## Features

- Decentralized identity management
- Peer-to-peer identity block distribution
- Cryptographic identity verification
- Cross-platform support (Windows and Unix-based systems)
- Automatic peer discovery and network maintenance

## Documentation

- [Synopsis](docs/synopsis.md) - The motivations behind this project
- [How It Works](docs/info.md) - Technical aspects of the system and how it achieves its goals
- [Developer Documentation](docs/developer/) - Understand the source code and integrate Nomicle into your applications
- [Downloads](docs/download.md) - Download the source code and run it for yourself
- [Get Started](docs/tutorial.md) - How to get Nomicle up and running on your computer
- [Bootstrap Servers](docs/bootstrap.md) - A list of known public bootstrap servers

## Papers

### Nomicle: A Self-Sovereign Identity System

- [PDF Version](docs/Nomicle.pdf)

## Future Ideas & Todos

- **Trust Authority**
  - Allow domain owners to use their TLS certificates for signing identities
  - Requires changes to the NCLE file spec

- **Rust Library**
  - A Nomicle library for Rust programs

- **Swift Library**
  - A Nomicle library for Swift programs

- **Implement support for blob mode**
  - Blob mode allows the system to treat the identifier as binary data rather than text
  - This means you can use any kind of file, e.g. an image, as your identifier

- **Nomicle Console**
  - Issue commands to the system
  - Two particular ones that could be useful are:
    - "self-destruct" to destroy all instances of your current identity
    - "boomerang" to check if your version of an identity is the dominant one

- **Key Extractor**
  - A tool for extracting the public key out of a nomicle and exporting it as a PEM file

- **Logging**
  - Access logging; configurable in a conf file

- **Black/Whitelists**
  - Black/Whitelisting identities by identifier and/or public key

- **Connection Capping**
  - Allow the user to configure a cap on peer connections
  - Currently infinite (node connects to as many peers as it can discover)

## See Also

As an end user, you won't really be interacting with Nomicle directly other than to set your identifier and start/stop the programs. *Nomicle is designed to be used by other applications on your computer while running silently in the background.*

A few other NORACO projects are designed to work in tandem with Nomicle. To get a proper feel for it, we recommend you also download and run this program simultaneously with Nomicle:

- [xTalk](https://github.com/alimahouk/xtalk) - A complementary project that works with Nomicle

If you're an application developer, be sure to take a look at the [developer documentation](docs/developer/) to see how you can integrate Nomicle into your own apps.

## License

This project is licensed under the terms specified in the LICENSE file.

## Author

Created by alimahouk

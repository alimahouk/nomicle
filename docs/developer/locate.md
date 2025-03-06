# How to Locate a Particular Nomicle

[← Back to Developer Documentation](../README.md)

A nomicle is a binary file which you may parse yourself based on the specification defined on this site or by using one of the available Nomicle libraries. The Seeder saves nomicles in the repository directory defined in the Nomicle configuration file. The filename is the SHA256 digest of the identifier within it.

## File Location

Assuming the default location is being used for the repository, to load the nomicle for the identifier 'foobar', your app would check if a file exists at the path:

- macOS/Linux: `/usr/local/var/ncle/blocks/c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.ncle`
- Windows: `%APPDATA%\NCLE\blocks\c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.ncle`

## Using the Probes File

If no such file exists, your app needs to add the identifier it needs to the Probes file. Calculate the SHA256 digest string of it (look up how to generate it with the programming language you're using) and append it to the file followed by a newline character.

**Never overwrite the contents of the Probes file; always append to it.**

In the case of 'foobar', you would open the Probes file in text mode, append `c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2\n` to it, and then close the file.

The Seeder will talk to other Nomicle installations on the network in an attempt to locate the nomicle for any identifiers in the Probes file. Your app needs to periodically poll the file path in the repository until the nomicle file exists there for it to access.

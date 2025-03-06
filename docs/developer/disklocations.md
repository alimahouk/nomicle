# Disk Locations of Interest

[← Back to Developer Documentation](../README.md)

These are the default locations of the following files. Keep in mind the user may choose to modify them. If your app reads any of these files, it would be wiser to parse the Nomicle config file and determine file paths from there rather than hard-coding them.

## Nomicle Repository Directory

You may choose to change this path to point to a directory being hosted by a web server and make your repository available for downloads over HTTP. The server hosting this website currently does this, e.g. you can download the nomicle for "alimahouk" [here](https://github.com/alimahouk/nomicle/raw/main/instance/blocks/cbce197fd7f18a82e1aee3d710b8f88404b458852b715b524f61c7f1b4140e4e.ncle).

- macOS and Linux: `/usr/local/var/ncle/blocks/`
- Windows: `%APPDATA%\NCLE\blocks\`

## Fortifier Configuration File

- macOS and Linux: `/usr/local/etc/ncle/fort.conf`
- Windows: `%APPDATA%\NCLE\fort.conf`

## Nomicle Configuration File

This text file contains a list of space-separated key-value pairs delimited by newlines. Your app can parse this file to determine the paths to Nomicle-related files. **If there's one file that should always be at its default location, it's this one!** Moving this file elsewhere is not recommended.

- macOS and Linux: `/usr/local/etc/ncle/ncle.conf`
- Windows: `%APPDATA%\NCLE\ncle.conf`

## Hosts File

A text file containing a list of the IP addresses and port numbers of other known Nomicle installations.

- macOS and Linux: `/usr/local/var/ncle/hosts`
- Windows: `%APPDATA%\NCLE\hosts.txt`

## Probes File

This text file contains a list of identifier tokens (i.e. their SHA256 digests in hexadecimal form; delimited by newlines) for which no nomicle currently exists in the repository.

- macOS and Linux: `/usr/local/var/ncle/probes`
- Windows: `%APPDATA%\NCLE\probes.txt`

## Identity File

*Note that this file has no extension.*

- macOS and Linux: `/usr/local/share/ncle/id`
- Windows: `%APPDATA%\NCLE\id`

## Private Key

- macOS and Linux: `/usr/local/etc/ncle/privkey.pem`
- Windows: `%APPDATA%\NCLE\privkey.pem`

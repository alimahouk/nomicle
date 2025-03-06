# Quick Start Guide

[← Back to Developer Documentation](../README.md)

This guide illustrates a quick and clear path for using Nomicle in an example program that encrypts a message to be sent to someone with the identifier 'foobar'.

## Steps

### 1. Include the library

Import [PyNomicle](lib.md#pynomicle) if you're using Python or link against [libcnomicle](lib.md#libcnomicle) if you're using C or some other programming language derived from it (e.g. C++, Objective-C/C++, etc.)

### 2. Parse the config file

The config file tells you where the files and directories you need are located (see [Disk Locations of Interest](disklocations.md)). If no config file exists, then assume that no Nomicle installation currently exists on the system and display some sort of error message.

### 3. Load the private key

Load the user's Nomicle private key, which is an elliptic curve private key. The location of the file will be in the config file.

### 4. Load foobar's public key from their nomicle

Create a SHA256 digest string of 'foobar', which will be 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2'. Append the '.ncle' file extension to this string then check if a file exists within the Nomicle repository (the path to which you would've obtained from the config file) with that name.

### 5. If the file exists…

Either use the library to load it as a data structure you can use or refer to the documentation and parse the bytes yourself. The data structure will contain a member with foobar's elliptic curve public key. Use the Diffie-Hellman scheme (the user's private key + foobar's public key) to encrypt your message and broadcast it across the network to other instances of your program. Ideally, you would include some metadata in the message such as the identifier of the intended recipient so that other instances of your program can tell whether they need to attempt to decrypt the message or not. Make sure to somehow bundle the local user's public key (which can be derived from their private key) within that message so that foobar may be able to decrypt it once they receive it (also using the Diffie-Hellman scheme, except the keys will be reversed).

### 6. If the file does not exist…

Append the SHA256 digest string you calculated ('c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2') to the Probes file (see [How to Locate a Particular Nomicle](locate.md)). Periodically poll for whether the file `c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2.ncle` exists within the block repository. This could happen within a short period of time or it may take a while. It may never appear if nobody on the network is using 'foobar' as their identifier; there's no way to tell. You could program some sort of timeout logic into your app so that if the file does not appear within an hour, it assumes no such identifier exists on the network.

If and when the file appears, go to step 5.

## Example Implementation

[xTalk](https://github.com/alimahouk/xtalk) is a sophisticated example of a messaging service powered by Nomicle. Feel free to browse its source code and documentation for inspiration.

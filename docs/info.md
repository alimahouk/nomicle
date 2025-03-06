# How It Works

[← Back to Main Documentation](index.md)

Nomicle allows you to create and associate a cryptographic key with an identifier of your choice (akin to your favourite online username) without depending on a third party. For example, you might want the name "slinky" to allow people to send messages addressed to you over a network.

## System Components

The Nomicle system is comprised of two programs:

- The **Fortifier**
- The **Seeder**

## How It Works

The Fortifier program running on your computer bundles your identifier with a key that others can use to encrypt messages they want to send you and then uses your computer's processing power to strengthen your key. This means that even if someone else somewhere happens to also choose "slinky" as their identifier later on, everyone will still end up using your key to encrypt messages they send to "slinky" (assuming you and the other slinky are both on the same network, like the public internet) and only you can decrypt them to view them.

There's no central database anywhere that keeps track of identities. The Seeder program on your computer distributes your identity file, or "block", to the Seeders running on other people's computers on the Nomicle network and fetches the blocks of others for you when you need to do something with their public key (e.g. to encrypt a message to send to them).

You own your Nomicle key and it can be used for anything you would expect a cryptographic key to do, such as:

- Encryption
- Signing
- Verifying digital signatures

This was an extremely simplified description of Nomicle and how it works. For an in-depth technical description, you can [read the paper](XP002.pdf).

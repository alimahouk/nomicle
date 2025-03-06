# Synopsis

[← Back to Main Documentation](index.md)

## The Problem

The need to identify things in a networked, digital realm is fundamental to its operation, from IP and MAC addresses at the bottom level to email addresses and domain names at the top level. In addition to coming up with a suitable identity scheme, the need to prove identity ownership at any point in time is equally necessary.

Ambiguity inevitably arises when two or more entities choose the same identifier to represent themselves. Historically, trust-based centralised models have been used to solve this problem, e.g. a database on a server. The administrator of that database effectively decides on the rules of identity allocation and may choose to prevent or allow third parties to make use of their identity scheme. Users trust the admin to safeguard existing identities and abide by their proclaimed allocation rules. This leads to "siloisation" as different parties decide they need to recreate an identity scheme that is under their control and tailored to their specific needs and rules.

## The Solution

In a decentralised model, trust in any form, such as timestamps, does not work for the resolution of identity ambiguity and stalemates. Instead, we propose a scheme based on consensus via cryptographic proof that can resolve identity ambiguity with the added benefit of being universally applicable.

[Read the full paper](XP002.pdf)

# frozenkrill vs hardware wallets

The recommended way to use bitcoin nowadays is:

- for average amounts: get a hardware wallet, create a BIP-39 seed phrase with a password and backup the seed to paper or (preferably) a metal plate in multiple places (for instance, to multiple geodistributed vaults). Everything should be done offline and all transactions should be air-gapped (through PSBT files exchanged by SD cards or QR codes)
- for high amounts: same as above, but the wallet should be configured to require multiple signatures ("multisig"), like 2-of-3, 3-of-5 etc. For each signature a different hardware wallet is used and they must be geodistributed and preferably controlled by multiple entities. If a high number of signatures and hardware wallets is used, a paper/metal seed backup _can_ be optional

This setup works very fine for many people in many circumstances. But it requires physical security and physical stability. It's ideal for sedentary people in safe countries. But consider that most of world's population may be living in non ideal situations.

## When physical security and stability isn't a given
Consider the following:
- People that travel frequently through national borders (like digital nomads)
- Zones under war or violent conflict
- Places where kidnapping or home invasion is common, like ghettos or slums (or "developing" countries in general)
- People that live under authoritarian regimes or are political dissidents
- Places where natural disasters are common, like fire, landslides or flooding
- People that are just bad with physical things and will break or lose anything they can touch

For these people and circumstances, a digital backup (complementing or replacing physical ones), may be safer than just physical ones, and this is where `frozenkrill` may be useful.

But you may ask:
> In this particular cases, why not just save the seed phrase digitally? It's protected by the seed password, right? RIGHT?

## Why the seed password isn't good enough

There are basically two reasons that makes BIP-39 seed passwords unsecure:

1) Passwords in general are weak because humans are bad at generating entropy
2) The cryptography of BIP-39 seed passwords hasn't been designed to secure against brute-force attacks

`frozenkrill` addresses both points, respectively, by:

1) _Strongly encouraging_ and facilitating the use of [keyfiles](./keyfiles.md) to provide additional entropy
2) Correctly employing cryptography designed to resist against brute-force attacks

So, with `frozenkrill` an encrypted wallet may be securely stored in a digital medium because it designed to survive attacks by malicious parties. It can be stored along other files in one or more storage providers, including free or cheap email and password managers accounts or really anywhere on internet.

**But it can never be generated on a non-trusted computer, specially a non-trusted computer connected to internet**

## The problem of generating the keys/seeds

Hardware wallets and paper/metal for backup seeds are recommended because:
1) They are simple enough to be safely handled even by people that are not "good with computers"
2) And in case of hardware wallets, they are simple enough to be audited by those who are "tech-savvy" (at least in theory)

It's a known fact that most digital devices are infested by malware due to ignorance and/or recklessness of users and even well maintained devices may contain backdoors or exploitable bugs due the opacity of most software and hardware (i.e most software and hardware are not open-source and have a big attack surface).

So using a computer to handle keys and passwords is hopeless because they will be leaked?

For non tech-savvy or extremely paranoid people, yes, a computer is too risky compared to a hardware wallet plus plain paper/metal.

But for many tech-savvy users it's a reasonable choice supposing that:
- Open-source software is safe enough
- Hardware vendors like AMD/Intel (or even Apple) can be trusted
- The user will spend time to reduce the surface attack and configure a clean system

For specific security considerations on how to safely use `frozenkrill`, see [this document](./security.md)
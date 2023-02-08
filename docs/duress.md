# Duress wallet (aka plausible deniability aka decoy wallet)
The BIP-39 seed password is weak against a brute force attack, but there is useful use case for it: plausible deniability under coercion (duress)

## The $5 Wrench Attack
![XKCD about the wrench attack](./images/xkcd_security.png)

[https://xkcd.com/538/](https://xkcd.com/538/)

If someone gets physical access to your _persona_ then there is no cryptography, hardware wallet or vault than can completely save you (even multisigs may be not enough, see below).

Most people will eventually yield under violence and hand over keys and passwords to the aggressor. But there is still an option to limit _how much_ these keys hold. You don't need to put all your eggs in one basket.

## Decoy wallets (or simply, multiple wallets)

So one idea is leave the default wallet with an empty seed password and avoiding putting the _bulk_ of one's money here, but instead put higher values on non-empty seed password wallets. In `frozenkrill`'s nomenclature these are called respectively _the duress wallet (a decoy)_ and the _non duress wallet (a "real" one)_.

But these are just conventions. In fact you can create many non duress wallets for the same seed and even a wallet with a password may not contain most of the funds. 

Ideally there are multiple passwords creating multiple wallets each one with a fraction of the funds but in practice remembering too many uncorrelated good passwords is unfeasible.

(there are also other practical difficulties here, for instance the aggressor may find out looking at the blockchain or tax returns how much money you controls and then proceed to extract everything, therefore techniques like coinjoin and avoiding kyc procedures may help, but this is out of scope of this document)

But even with its flaws, we suggest the users to at least consider creating a decoy wallet if physical coercion is a real threat and they have good memory.

Also note that this concept isn't restricted to seed passwords, for instance a hardware wallet in a vault may be the decoy wallet, while one hidden in a computer the non duress one. Creativity is useful here.

## Decoy wallets or multisigs?
![Why not both?](./images/whynotboth.gif)

If one's is afraid of physical coercion, then the common wisdom is to just use multisig and geographically distribute the keys to slow down the attack and make it completely fail.

This is good and recommended but it's not a guarantee that everyone will be able to perfectly distribute and secure everything, specially given `frozenkrill`'s assumptions and uses cases. This wallet has been built [for people that have limited access to secure and stable physical locations](./hw.md#when-physical-security-and-stability-isn-t-a-given).

For instance, even if there are friends or family holding on keys for a multisig and being oriented to never give up the key or signature if you are under coercion, the plan may completely fail when they actually see the violence taking action.

So even in these cases it's possible to have different multisig wallets, each one being controlled by different combinations of seed passwords.

(not necessarily all wallets offer this feature, but `frozenkrill` does)

## So let's do it?

While we suggest everyone to consider creating a duress wallet, as it is a much more complex setup with higher cognitive load we can't just recommend it as a "best-practice" because the risks may not offset the gains.

There is a real danger of losing funds if one forgets or mistypes a complex and long seed password. At least it will require a lot of computational resources to brute force it.

As with any advice, take it with a grain of salt and consider your own context, capabilities and threat models.

If in doubt, don't do it. And if you are going to do, double check everything and consider employing shorter passwords than usual.
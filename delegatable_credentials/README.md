# Delegatable credentials

Provides 2 variations:
1. Ad-hoc delegation where credential owner chooses a set of issuer public keys and proves that the credential was issued by one of the key. Based on the paper [Protego: A Credential Scheme for Permissioned Blockchains](https://eprint.iacr.org/2022/661). [Code](./src/protego)
2. Here there is a root issuer which can issue a credential to anyone with the permission to reissue the credential with or without additional attributes. Based on the paper [Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680). [Code](./src/msbm)
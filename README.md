# TumbleBitSetup
TumbleBit Setup

TumbleBit is a unidirectional unlinkable payment hub that allows parties to make fast, anonymous, off-blockchain payments through an untrusted intermediary called the Tumbler. This repository implements an important aspect of the TumbleBit setup protocol. 

The security of the TumbleBit protocol rests on the assumption that the Tumbler's RSA public key (N, e) defines a permutation over Z_N. In the absence of this assumption, the Tumbler can steal bitcoins. At the same time, the cryptographic proofs of security for the TumbleBit protocol (which are in the real/ideal paradigm) rest on the assumption that payers and payees (Alice and Bob) verify a publicly-verifiable zero-knowledge proof of knowledge that the Tumbler knows the secret key corresponding to his RSA public key.

Because the Tumbler is charged with choosing its own RSA public key, it is important to ensure that the Tumbler did not choose an "adversarial" key that allows it to steal bitcoins. As such, the TumbleBit protocol has a setup phase that forces the Tumbler to prove that his key was chosen "properly". Specifically, the Tumbler must provide a pair of zero-knowledge proofs along with his RSA public key. The first is a new zero-knowledge proof protocol that we designed. This protocol proves that the RSA public key (N, e) defines a permutation over Z_N. We design the protocol, prove its security, provide a full specification and implementation. The second zero-knowledge proof protocol is by Poupard and Stern from 2000, and proves knowledge of the factorization of the RSA modulus N. For the Poupard-Stern protocol, we set parameters and provide a full specification. When any payer Alice or payee Bob wants to participate in the TumbleBit protocol with this Tumbler, they must first validate this pair of zero knowledge proofs. This repository has the implementation of this pair of zero-knowledge proofs.

For more details, see setup.pdf that can be found in this repository.


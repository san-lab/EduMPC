# EduMPC

Simple educational MPC brick set based on libp2p.

### Usage
```
go build -o main
./main -enable protocol
```

There are different multiparty protocols and showcases of attacks on them available in the framework:
* **Oblivious Transfers**: 2-party protocol where sender has two encrypted messages and recieving party can only decrypt one of them, in such a way that the sender party has no information on which one has been decrypted. It is one of the building blocks of complex MPC protocols (brief explanation of the cryptography: https://crypto.stanford.edu/pbc/notes/crypto/ot.html).
  
* **Multiplicative-to-Additive Function**: 2-party protocol where parties wish to turn a secret shared in a multiplicative way (shared_secret = a * b) into an additive one (shared_secret = a' + b') without leaking any information of their respective private secrets. It is the other main building block of MPC protocols. Our implementation is based on Paillier cryptosystem.
  
* **"Parity" Attack**: attack on implementations of Lindell Two-Party ECDSA Signing (https://eprint.iacr.org/2017/552), where outputting the validity or not of the resulting signature leads to a private key leakage (described in: https://www.fireblocks.com/blog/lindell17-abort-vulnerability-technical-report/).
  
* **Attack on implementations GG18/GG20** (one the most popular threshold EDCSA protocols, https://eprint.iacr.org/2020/540.pdf) based on the use of malformed zero-knowledge proofs and lack of verification (described in: https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report/)

---

SepiorSDK - This branch has been created to test Sepior MPC SDK

It expects the Sepior Client SDK to be available locally (or one needs to login to gitlab)
Edit the "replace" directive in the go.mod file to point to your local SDK:
`replace gitlab.com/sepior/go-tsm-sdk => /home/yourusr/go/src/gitlab.com/go-tsm-sdk`


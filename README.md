# What does hybrid post-quantum key exchange cost a microservice?

📄 **Paper (PDF): [pq-tls-microservices.pdf](pq-tls-microservices.pdf)**

X25519MLKEM768 measured in Go's standard TLS stack (Go 1.24, no third-party code): primitives, 28 handshake
configurations (4 certificate types, with/without mTLS, resumption, mixed estates) and bytes per flight.

* Mutual-TLS handshake grows from 1,721 to 4,032 bytes; the ClientHello from 224 to 1,446 bytes
  (one Ethernet segment, two behind a VPN or at the IPv6 minimum MTU).
* With ECDSA certificates: +47% server CPU and +56% client CPU per full mTLS handshake. With RSA-3072: +4%.
* Session resumption still pays the key exchange; hybrid clients talking to classical servers pay the bytes for nothing.
* No extra round trip: about +1 ms in a data centre, +4% on broadband, +17–21% on 1 Mbit/s and slower links.

## Reproduce

```bash
go build -o pqbench ./cmd/pqbench
./pqbench prims
./pqbench run -n 300 -reps 7      # about 5 minutes; run on an otherwise idle machine
python src/analyse.py
cd paper && latexmk -pdf main.tex
```

## AI assistance

An AI assistant (Claude, Anthropic) helped write the benchmark code and draft text. The author designed the study,
reviewed the code and results, and is responsible for the content.

## Licence

MIT

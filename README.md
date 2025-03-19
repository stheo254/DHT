# DHT
## Overview

This project implements a Distributed Hash Table (DHT) in the C programming language. A DHT is a decentralized distributed system that provides a lookup service similar to a hash table, where key-value pairs are stored across multiple nodes.

### Key Features:

Node insertion and deletion

Key-value storage and lookup

Consistent hashing for efficient distribution

Peer-to-peer communication

Fault tolerance and scalability

Chord Protocol implementation for efficient key lookup

This project uses the Chord protocol for efficient key lookup and node management. Chord is a peer-to-peer algorithm that organizes nodes in a circular ring and supports efficient data lookup in O(log N) time.

### How Chord Works:

Consistent Hashing: Nodes and keys are assigned identifiers using a hash function (e.g., SHA-1) and are placed on a circular ring.

Finger Table: Each node maintains a routing table (finger table) that speeds up lookups by storing links to other nodes.

Lookup Operation: To locate a key, Chord uses the finger table to jump through the ring, reducing the search time to O(log N).

Node Join and Leave: When a node joins or leaves, Chord updates its neighbors and redistributes key responsibilities to maintain consistency.

### Usage:

Compile:
```
cmake -B build -DCMAKE_BUILD_TYPE=Debug
make -C build
```

Run:
```
./build/webserver
```

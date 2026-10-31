# coqui-peer WebCrypto method (experimental)

This is the **canonical** JavaScript source of the browser-capable `p256-spki` method for [coqui-peer](https://github.com/Boriken-Dev/coqui-peer). Applications such as Canoa must consume or vendor this module **unchanged** with an explicit source revision, rather than own a different handshake protocol.

The method implements mutual P-256 ECDSA/SHA-256 proof on an already protected, reliable, ordered message transport. Each peer identity is `sha256:` plus SHA-256 of the DER SubjectPublicKeyInfo bytes. It is **distinct** from a TLS-certificate identity used by `coqui-peer-tls`.

`profile.id` is `dev.boriken.coqui.peer-webcrypto/v1`. The wire flow is `hello → challenge → proof → accept`. Each side signs a role-separated transcript binding the profile, both public keys, and both fresh 32-byte nonces. The initiator must pin the expected server PeerId. The responder must independently check its trust database through `allowClient(peerId)` before accepting a proven client. **Proof is not pairing**: unknown keys must not be trusted automatically.

Browsers persist non-extractable `CryptoKey` private keys through IndexedDB structured cloning; the PWA and extension may have different identities. Never export private keys, reveal their references to webpages, or permit remote tools to change trust decisions.

## Usage

```js
import {generateIdentity, createInitiator} from './src/index.mjs';
const identity = await generateIdentity(); // Persist with loadOrCreateIdentity in browsers
const auth = await createInitiator(identity, pinnedServerPeerId);
await messageChannel.send(auth.hello());
const proof = await auth.answer(await messageChannel.receive());
await messageChannel.send(proof);
const verifiedServerPeerId = await auth.finish(await messageChannel.receive());
// Only NOW may the application begin ACP, MCP or other privileged traffic.
```

Node 22+ tests: `npm test`.

## Integration boundaries

- `coqui-net-transport`: WebTransport, WSS fallback, stream framing, queuing of messages through the authentication boundary.
- `coqui-peer`: peer identity, pairing, trust and this authentication method.
- Canoa/AI6/Guatiao: application/session protocols, UI, permission policy.

The JavaScript state machine is an **experimental method implementation**. It does not claim to implement the Rust `coqui_peer::Method` trait; a compatible native Rust implementation and cross-language conformance vectors are still required before claiming full interoperability. The wire format is a draft and cannot yet be regarded as a published standard.

No browser-side key is automatically entered into the Rust `TrustStore`; hosts must implement explicit enrollment/revocation and map `p256-spki` key material to the store.

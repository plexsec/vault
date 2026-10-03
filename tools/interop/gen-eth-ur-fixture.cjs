// Generates the Ethereum QR protocol fixture from the *reference implementation*, so the
// Swift tests compare against what a wallet actually sends rather than against our own
// encoder. Self-generated fixtures are what let a wrong CBOR shape survive test suites in
// both directions (amendment 25).
//
//   mkdir -p /tmp/mmqr && cd /tmp/mmqr && npm init -y
//   npm install @keystonehq/bc-ur-registry-eth@0.22.1 \
//               @keystonehq/bc-ur-registry@0.7.0 @ngraveio/bc-ur
//   cd <repo> && NODE_PATH=/tmp/mmqr/node_modules \
//     node tools/interop/gen-eth-ur-fixture.cjs \
//     > ios/Packages/VaultKit/Tests/VaultKitTests/Fixtures/eth_ur_reference.json
//
// The library versions are recorded inside the fixture. Node is deliberately not a build
// dependency of the repo: the fixture is committed and checked, exactly like the
// ethereum/tests RLP vectors.
const { EthSignRequest, ETHSignature } = require('@keystonehq/bc-ur-registry-eth')
const { CryptoKeypath, PathComponent } = require('@keystonehq/bc-ur-registry')
const { UREncoder } = require('@ngraveio/bc-ur')

// Very small RLP encoder, so the payload below is built from its fields rather than typed
// in as hex. A hand-written hex string is how this fixture first shipped with chain 1 and
// 1 ETH in it while claiming chain 137 and 1.5 POL — the Swift test noticed, which is the
// point of comparing against a fixture at all.
const bytes = value => {
  if (Buffer.isBuffer(value)) return value
  if (typeof value === 'string') return Buffer.from(value, 'hex')
  if (value === 0n || value === 0) return Buffer.alloc(0)
  let hex = BigInt(value).toString(16)
  if (hex.length % 2) hex = '0' + hex
  const raw = Buffer.from(hex, 'hex')
  return raw[0] === 0 ? Buffer.concat([Buffer.from([0]), raw.subarray(1)]) : raw
}
const rlpBytes = value => {
  if (Array.isArray(value)) return rlpList(value)
  const raw = bytes(value)
  if (raw.length === 1 && raw[0] < 0x80) return raw
  if (raw.length < 56) return Buffer.concat([Buffer.from([0x80 + raw.length]), raw])
  return Buffer.concat([Buffer.from([0xb7 + raw.length.toString(16).length / 2]), bytes(raw.length), raw])
}
const rlpList = items => {
  const body = Buffer.concat(items.map(rlpBytes))
  if (body.length < 56) return Buffer.concat([Buffer.from([0xc0 + body.length]), body])
  return Buffer.concat([Buffer.from([0xf7 + bytes(body.length).length]), bytes(body.length), body])
}

// Inputs chosen to line up with the app's own derivation and signing fixtures: the leaf path
// m/44'/0'/0'/0/0 under master fingerprint 5436d724, on chain 137 (Polygon), with the same
// unsigned EIP-1559 payload the app's `fee_market_chain_137` vector signs (nonce 1, 1 gwei
// tip, 30 gwei cap, 21000 gas, the 0x35…35 recipient, 1.5 POL, no data, empty access list).
const signData = Buffer.concat([
  Buffer.from([0x02]),
  rlpList([137, 1, 1_000_000_000, 30_000_000_000, '5208', '35'.repeat(20), 1_500_000_000_000_000_000, '', []]),
])
const inputs = {
  requestId: '00112233445566778899aabbccddeeff',
  signData: signData.toString('hex'),
  dataType: 4,
  path: [44, 0, 0, 0, 0],
  hardened: [true, true, true, false, false],
  sourceFingerprint: '5436d724',
  chainId: 137,
  signature: 'ab'.repeat(65),
  origin: 'PlexVault',
}

const keypath = new CryptoKeypath(
  inputs.path.map((index, i) => new PathComponent({ index, hardened: inputs.hardened[i] })),
  Buffer.from(inputs.sourceFingerprint, 'hex')
)

const requestUR = new EthSignRequest({
  requestId: Buffer.from(inputs.requestId, 'hex'),
  signData,
  dataType: inputs.dataType,
  derivationPath: keypath,
  chainId: inputs.chainId,
}).toUR()

const signatureUR = new ETHSignature(
  Buffer.from(inputs.signature, 'hex'),
  Buffer.from(inputs.requestId, 'hex'),
  inputs.origin
).toUR()

const cborOf = ur => (Buffer.isBuffer(ur.cbor) ? ur.cbor : Buffer.from(ur.cbor))

const fixture = {
  note: 'generated from the reference implementation; do not hand-edit',
  generator: {
    script: 'tools/interop/gen-eth-ur-fixture.cjs',
    libraries: {
      '@keystonehq/bc-ur-registry-eth': require('@keystonehq/bc-ur-registry-eth/package.json').version,
      '@keystonehq/bc-ur-registry': require('@keystonehq/bc-ur-registry/package.json').version,
      '@ngraveio/bc-ur': require('@ngraveio/bc-ur/package.json').version,
    },
  },
  outerTag: 'absent',
  request: { inputs, ur: new UREncoder(requestUR, 1000).nextPart(), cborHex: cborOf(requestUR).toString('hex') },
  signature: { ur: new UREncoder(signatureUR, 1000).nextPart(), cborHex: cborOf(signatureUR).toString('hex') },
}

for (const [name, ur] of [['request', requestUR], ['signature', signatureUR]]) {
  const bytes = cborOf(ur)
  if (bytes[0] === 0xd9) throw new Error(`${name}: the reference emitted an outer tag after all`)
}
console.log(JSON.stringify(fixture, null, 1))

// Independent ESP fixture generator using Node's OpenSSL AES-GCM, not Go.
// Run: node internal/photonclient/esp/testdata/vector.cjs
// RFC 4106 sections 3-5 and RFC 4303 section 2 define the wire layout.
const { createCipheriv } = require('node:crypto');
const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const salt = Buffer.from('a0a1a2a3', 'hex');
const header = Buffer.from('1020304000000001', 'hex');
const iv = Buffer.from('0000000000000001', 'hex');
const inner = Buffer.from('450000180001000040110000c0000201c633640201020304', 'hex');
const plaintext = Buffer.concat([inner, Buffer.from('01020204', 'hex')]);
const cipher = createCipheriv('aes-128-gcm', key, Buffer.concat([salt, iv]));
cipher.setAAD(header);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
console.log(Buffer.concat([header, iv, encrypted, cipher.getAuthTag()]).toString('hex'));

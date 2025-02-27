const forge = require('node-forge');

const E = [
  32, 1, 2, 3, 4, 5, 4, 5,
  6, 7, 8, 9, 8, 9, 10, 11,
  12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21,
  22, 23, 24, 25, 24, 25, 26, 27,
  28, 29, 28, 29, 30, 31, 32, 1
];

function desDecryptWithDetails(ciphertextHex, keyHex) {
    const keyBytes = forge.util.hexToBytes(keyHex);
    const ciphertextBytes = forge.util.hexToBytes(ciphertextHex);
    let ciphertext = Buffer.from(ciphertextBytes, 'hex');
    const des = forge.des.createDecryptionCipher(
        forge.util.createBuffer(keyBytes),
        'ECB'
    );

    let roundKeys = [];

    function decimalToHex(decimal) {
      return decimal.toString(16);
    }
    
    function fFunction(R, roundKey) {
      let expandedR = 0n;
      for (let i = 0; i < 48; i++) {
          expandedR |= ((BigInt((R >> (32 - E[i])) & 1)) << BigInt(47 - i));
      }
  
      let xorResult = expandedR ^ BigInt(parseInt(roundKey.toString('hex'), 16));
      console.log("f function output:", xorResult.toString(16));
      return Number(xorResult & BigInt(0xFFFFFFFF));
    } 

    roundKeys.push(...des.algorithm._keys.slice(0, 16))
    roundKeys = roundKeys.map(k => decimalToHex(k));
    let permutedText = 0n;
    
    for (let i = 0; i < 64; i++) {
      permutedText |= ((BigInt((ciphertext[i >> 3] >> (7 - (i % 8))) & 1)) << BigInt(63 - i));
    }

    let L = Number(permutedText >> 32n) & 0xFFFFFFFF;
    let R = Number(permutedText & BigInt(0xFFFFFFFF));

    for (let i = 0; i < 16; i++) {
        let temp = L;
        L = R;
        R = temp ^ fFunction(R, roundKeys[i]);
    }

    des.start();
    des.update(forge.util.createBuffer(ciphertextBytes));
    des.finish();

    console.log('16 Round Keys:');
    roundKeys.forEach((k, i) => console.log(`Round ${i + 1}: ${k}`));

    return des.output.toString('utf8').replace(/\x00+$/, '');
}

const ciphertext = 'caeda2655fb73873';
const key = '4C4F564543534E44'; 

console.log('Decrypting...');
const plaintext = desDecryptWithDetails(ciphertext, key);
console.log('\nFinal Decrypted Text:', plaintext);
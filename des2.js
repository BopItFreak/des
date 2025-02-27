const { Buffer } = require('buffer');

// Initial Permutation Table
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
];

// Final Permutation Table
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25
];

// Expansion (E) Table
const E = [
  32, 1, 2, 3, 4, 5, 4, 5,
  6, 7, 8, 9, 8, 9, 10, 11,
  12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21,
  22, 23, 24, 25, 24, 25, 26, 27,
  28, 29, 28, 29, 30, 31, 32, 1
];

// Permutation (P) Table
const P = [
  16, 7, 20, 21, 29, 12, 28, 17,
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25
];

// PC-1 table
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1,
  58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3,
  60, 52, 44, 36, 63, 55, 47, 39,
  31, 23, 15, 7, 62, 54, 46, 38,
  30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4
];

// PC-2 table
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28,
  15, 6, 21, 10, 23, 19, 12, 4,
  26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40,
  51, 45, 33, 48, 44, 49, 39, 56,
  34, 53, 46, 42, 50, 36, 29, 32
];
// Number of key shifts per round
const keyShifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

function leftRotate28(bits, shift) {
    return ((bits << shift) | (bits >>> (28 - shift))) & 0xFFFFFFF;
}

function generateRoundKeys(key) {
    let permutedKey = 0n;
    for (let i = 0; i < 56; i++) {
        permutedKey |= ((BigInt((key[i >> 3] >> (7 - (i % 8))) & 1)) << BigInt(55 - i));
    }

    let C = Number(permutedKey >> 28n) & 0xFFFFFFF;
    let D = Number(permutedKey & BigInt(0xFFFFFFF));
    let roundKeys = [];

    for (let i = 0; i < 16; i++) {
        C = leftRotate28(C, keyShifts[i]);
        D = leftRotate28(D, keyShifts[i]);
        let combinedKey = (BigInt(C) << 28n) | BigInt(D);
        let roundKey = Buffer.alloc(6);
        
        for (let j = 0; j < 48; j++) {
            let bit = (combinedKey >> BigInt(56 - PC2[j])) & 1n;
            roundKey[j >> 3] |= Number(bit) << (7 - (j % 8));
        }

        roundKeys.push(roundKey);
        console.log(`Round ${i + 1} Key:`, roundKey.toString('hex'));
    }
    return roundKeys;
}

function feistelFunction(R, roundKey) {
    let expandedR = 0n;
    for (let i = 0; i < 48; i++) {
        expandedR |= ((BigInt((R >> (32 - E[i])) & 1)) << BigInt(47 - i));
    }

    let xorResult = expandedR ^ BigInt(parseInt(roundKey.toString('hex'), 16));
    console.log("f function output:", xorResult.toString(16));
    return Number(xorResult & BigInt(0xFFFFFFFF));
}

function desDecrypt(ciphertext, key) {
    let roundKeys = generateRoundKeys(key).reverse();
    let permutedText = 0n;
    for (let i = 0; i < 64; i++) {
        permutedText |= ((BigInt((ciphertext[i >> 3] >> (7 - (i % 8))) & 1)) << BigInt(63 - i));
    }

    let L = Number(permutedText >> 32n) & 0xFFFFFFFF;
    let R = Number(permutedText & BigInt(0xFFFFFFFF));

    for (let i = 0; i < 16; i++) {
        let temp = L;
        L = R;
        R = temp ^ feistelFunction(R, roundKeys[i]);
    }

    let preOutput = (BigInt(R) << 32n) | BigInt(L);
    let finalText = 0n;
    for (let i = 0; i < 64; i++) {
        finalText |= ((preOutput >> BigInt(64 - FP[i])) & 1n) << BigInt(63 - i);
    }

    let decryptedBytes = Buffer.alloc(8);
    for (let i = 0; i < 8; i++) {
        decryptedBytes[i] = Number((finalText >> BigInt(56 - 8 * i)) & 0xFFn);
    }

    console.log("Decrypted plaintext:", decryptedBytes.toString('hex'));
}

const key = Buffer.from('4C4F564543534E44', 'hex');
const ciphertext = Buffer.from('caeda2655fb73873', 'hex');
console.log("Generating round keys...");
const roundKeys = generateRoundKeys(key);

console.log("Decrypting ciphertext...");
desDecrypt(ciphertext, key);
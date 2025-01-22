const crypto = require('crypto');

// Function to generate SHA-256 hash from one input
function SHA256Hash(hash) {
    // Generate the SHA-256 hash in hexadecimal format
    return crypto.createHash('sha256').update(hash).digest('hex');
}

// Example usage
const hash1 = "Hello";
const hash2 = "World";

// Generate separate hashes for each input
const hashValue1 = SHA256Hash(hash1);
const hashValue2 = SHA256Hash(hash2);

console.log(`Hash for hash1: ${hashValue1}`);
console.log(`Hash for hash2: ${hashValue2}`);


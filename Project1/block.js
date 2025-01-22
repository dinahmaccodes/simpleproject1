const crypto = require('crypto');

// Function to generate SHA-256 hash
function SHA256Hash(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
}

// Step 1: Define transaction hashes (h1, h2, h3, h4)
const h1 = SHA256Hash("Alice pays Bob 5 BTC");
const h2 = SHA256Hash("Charlie pays Dave 2.5 BTC");
const h3 = SHA256Hash("Eve pays Frank 1.25 BTC");
const h4 = SHA256Hash("George pays Hannah 0.75 BTC");

console.log("Leaf Hashes (Transactions):");
console.log(`h1: ${h1}`);
console.log(`h2: ${h2}`);
console.log(`h3: ${h3}`);
console.log(`h4: ${h4}`);

// Step 2: Compute intermediate hashes
const h12 = SHA256Hash(h1 + h2); // Hash of h1 and h2 combined
const h34 = SHA256Hash(h3 + h4); // Hash of h3 and h4 combined

console.log("\nIntermediate Hashes:");
console.log(`h12: ${h12}`);
console.log(`h34: ${h34}`);

// Step 3: Compute the root hash
const hRoot = SHA256Hash(h12 + h34);

console.log("\nMerkle Root:");
console.log(`hRoot: ${hRoot}`);

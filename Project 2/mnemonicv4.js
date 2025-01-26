const fs = require("fs");
const sha256 = require("sha256");
const secureRandom = require("secure-random");

// Function to generate 128 bits of entropy
function generateEntropy() {
  // Generate 16 random bytes (128 bits)
  let entropyBuffer = secureRandom.randomBuffer(16);
  // Convert entropy to a hexadecimal string 
  let entropyHex = entropyBuffer.toString("hex");
  return entropyHex;
}

// Function to calculate the checksum and append it to the entropy
function addChecksumToEntropy(entropyHex) {
  // Compute the SHA-256 hash of the entropy
  let hash = sha256(Buffer.from(entropyHex, "hex"));

  // Extract the first 4 bits of the hash as the checksum
  let checksumBits = parseInt(hash[0], 16).toString(2).padStart(4, "0");

  // Convert the entropy from hex to binary
  let entropyBits = BigInt("0x" + entropyHex).toString(2).padStart(128, "0");

  // Combine entropy bits with checksum bits
  let entropyWithChecksum = entropyBits + checksumBits;

  return entropyWithChecksum;
}

// Function to convert the entropy + checksum into a mnemonic
function convertEntropyToMnemonic(entropyWithChecksum, wordlist) {
  let mnemonicWords = []; // To store the resulting mnemonic words

  // Split the binary string into 11-bit chunks
  for (let i = 0; i < entropyWithChecksum.length; i += 11) {
    let group = entropyWithChecksum.slice(i, i + 11); // Take 11 bits at a time

    if (group.length === 11) {
      // Convert the binary group to a decimal index
      let wordIndex = parseInt(group, 2);

      // Use the index to fetch the word from the wordlist
      mnemonicWords.push(wordlist[wordIndex]);
    }
  }

  return mnemonicWords;
}

// Main function
function main() {
  try {
    // Step 1: Load the wordlist
    let wordlistFile = "./mywordslist.txt"; // Path to the wordlist file
    let wordlist = fs.readFileSync(wordlistFile, "utf8").split("\n").map((word) => word.trim());

    // Ensure the wordlist contains exactly 2048 words
    if (wordlist.length !== 2048) {
      throw new Error("The wordlist must contain exactly 2048 words.");
    }

    // Step 2: Generate entropy
    let entropy = generateEntropy();
    console.log("Generated Entropy (Hex):", entropy);

    // Step 3: Add checksum to the entropy
    let entropyWithChecksum = addChecksumToEntropy(entropy);
    console.log("Entropy + Checksum (Binary):", entropyWithChecksum);

    // Step 4: Convert entropy with checksum to mnemonic
    let mnemonic = convertEntropyToMnemonic(entropyWithChecksum, wordlist);
    console.log("Generated Mnemonic (12 words):", mnemonic.join(" "));

  } catch (error) {
    console.error("Error:", error.message);
  }
}

// Run the main function
main();

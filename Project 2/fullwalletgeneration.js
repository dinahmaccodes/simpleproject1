const fs = require("fs");
const sha256 = require("sha256");
const secureRandom = require("secure-random");
const crypto = require("crypto");

// Function to generate 128 bits of entropy
function generateEntropy() {
  let entropyBuffer = secureRandom.randomBuffer(16); // 16 random bytes (128 bits)
  return entropyBuffer.toString("hex"); // Convert to hexadecimal string
}

// Function to calculate the checksum and append it to the entropy
function addChecksumToEntropy(entropyHex) {
  let hash = sha256(Buffer.from(entropyHex, "hex"));
  let checksumBits = parseInt(hash[0], 16).toString(2).padStart(4, "0");
  let entropyBits = BigInt("0x" + entropyHex).toString(2).padStart(128, "0");
  return entropyBits + checksumBits; // Combine entropy and checksum
}

// Function to convert the entropy + checksum into a mnemonic
function convertEntropyToMnemonic(entropyWithChecksum, wordlist) {
  let mnemonicWords = [];
  for (let i = 0; i < entropyWithChecksum.length; i += 11) {
    let group = entropyWithChecksum.slice(i, i + 11);
    if (group.length === 11) {
      let wordIndex = parseInt(group, 2);
      mnemonicWords.push(wordlist[wordIndex]);
    }
  }
  return mnemonicWords;
}

// Function to derive private keys and addresses from the mnemonic
function derivePrivateKeysAndAddresses(mnemonic, numAccounts = 5) {
  let accounts = [];
  for (let i = 0; i < numAccounts; i++) {
    // Derive deterministic private key
    let seed = sha256(mnemonic.join(" ") + i); // Add index for determinism
    let privateKey = crypto.createHash("sha256").update(seed).digest("hex"); // 64 hex characters

    // Generate Ethereum address (last 40 hex characters of keccak256 hash of public key)
    let publicKey = crypto.createECDH("secp256k1").generateKeys("hex"); // Mock public key generation
    let address = sha256(publicKey).slice(-40); // Use last 40 characters

    accounts.push({
      account: `Account ${i + 1}`,
      privateKey: `0x${privateKey}`,
      address: `0x${address}`,
    });
  }
  return accounts;
}

// Main function
function main() {
  try {
    // Step 1: Load the wordlist
    let wordlistFile = "./mywordslist.txt";
    let wordlist = fs.readFileSync(wordlistFile, "utf8").split("\n").map((word) => word.trim());

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

    // Step 5: Generate private keys and addresses
    let accounts = derivePrivateKeysAndAddresses(mnemonic);
    console.log("Generated Accounts:");
    accounts.forEach((account) => {
      console.log(`${account.account}:`);
      console.log(`  Private Key: ${account.privateKey}`);
      console.log(`  Address: ${account.address}`);
    });

  } catch (error) {
    console.error("Error:", error.message);
  }
}

// Run the main function
main();

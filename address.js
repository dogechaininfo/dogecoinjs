Dogecoin.Address = function (bytes) {
  if ("string" == typeof bytes) {
    bytes = Dogecoin.Address.decodeString(bytes);
  }
  this.hash = bytes;
  this.version = Dogecoin.Address.networkVersion;
  this.label = null;
};

Dogecoin.Address.networkVersion = 0x1E; // mainnet: 0x00   testnet: 0x6F

/**
 * Serialize this object as a standard Dogecoin address.
 *
 * Returns the address as a base58-encoded string in the standardized format.
 */
Dogecoin.Address.prototype.toString = function () {
  // Get a copy of the hash
  var hash = this.hash.slice(0);

  // Version
  hash.unshift(this.version);

  var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

  var bytes = hash.concat(checksum.slice(0,4));

  return Dogecoin.Base58.encode(bytes);
};

Dogecoin.Address.prototype.getHashBase64 = function () {
  return Crypto.util.bytesToBase64(this.hash);
};

/**
 * Parse a Dogecoin address contained in a string.
 */
Dogecoin.Address.decodeString = function (string) {
  var bytes = Dogecoin.Base58.decode(string);

  var hash = bytes.slice(0, 21);

  var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

  if (checksum[0] != bytes[21] ||
      checksum[1] != bytes[22] ||
      checksum[2] != bytes[23] ||
      checksum[3] != bytes[24]) {
    throw "Checksum validation failed!";
  }

  var version = hash.shift();

  if (version != 30) {
    throw "Version "+version+" not supported!";
  }

  return hash;
};
Dogecoin.ECKey = (function () {
	var ECDSA = Dogecoin.ECDSA;
	var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
	var rng = new SecureRandom();

	var ECKey = function (input) {
		if (!input) {
			// Generate new key
			var n = ecparams.getN();
			this.priv = ECDSA.getBigRandom(n);
		} else if (input instanceof BigInteger) {
			// Input is a private key value
			this.priv = input;
		} else if (Dogecoin.Util.isArray(input)) {
			// Prepend zero byte to prevent interpretation as negative integer
			this.priv = BigInteger.fromByteArrayUnsigned(input);
		} else if ("string" == typeof input) {
			var bytes = null;
			if (ECKey.isWalletImportFormat(input)) {
				bytes = ECKey.decodeWalletImportFormat(input);
			} else if (ECKey.isCompressedWalletImportFormat(input)) {
				bytes = ECKey.decodeCompressedWalletImportFormat(input);
				this.compressed = true;
			} else if (ECKey.isMiniFormat(input)) {
				bytes = Crypto.SHA256(input, { asBytes: true });
			} else if (ECKey.isHexFormat(input)) {
				bytes = Crypto.util.hexToBytes(input);
			} else if (ECKey.isBase64Format(input)) {
				bytes = Crypto.util.base64ToBytes(input);
			}
			
			if (ECKey.isBase6Format(input)) {
				this.priv = new BigInteger(input, 6);
			} else if (bytes == null || bytes.length != 32) {
				this.priv = null;
			} else {
				// Prepend zero byte to prevent interpretation as negative integer
				this.priv = BigInteger.fromByteArrayUnsigned(bytes);
			}
		}

		this.compressed = (this.compressed == undefined) ? !!ECKey.compressByDefault : this.compressed;
	};

	ECKey.privateKeyPrefix = 0x9E; // mainnet 0x80    testnet 0xEF

	/**
	* Whether public keys should be returned compressed by default.
	*/
	ECKey.compressByDefault = false;

	/**
	* Set whether the public key should be returned compressed or not.
	*/
	ECKey.prototype.setCompressed = function (v) {
		this.compressed = !!v;
		if (this.pubPoint) this.pubPoint.compressed = this.compressed;
		return this;
	};

	/*
	* Return public key as a byte array in DER encoding
	*/
	ECKey.prototype.getPub = function () {
		if (this.compressed) {
			if (this.pubComp) return this.pubComp;
			return this.pubComp = this.getPubPoint().getEncoded(1);
		} else {
			if (this.pubUncomp) return this.pubUncomp;
			return this.pubUncomp = this.getPubPoint().getEncoded(0);
		}
	};

	/**
	* Return public point as ECPoint object.
	*/
	ECKey.prototype.getPubPoint = function () {
		if (!this.pubPoint) {
			this.pubPoint = ecparams.getG().multiply(this.priv);
			this.pubPoint.compressed = this.compressed;
		}
		return this.pubPoint;
	};

	ECKey.prototype.getPubKeyHex = function () {
		if (this.compressed) {
			if (this.pubKeyHexComp) return this.pubKeyHexComp;
			return this.pubKeyHexComp = Crypto.util.bytesToHex(this.getPub()).toString().toUpperCase();
		} else {
			if (this.pubKeyHexUncomp) return this.pubKeyHexUncomp;
			return this.pubKeyHexUncomp = Crypto.util.bytesToHex(this.getPub()).toString().toUpperCase();
		}
	};

	/**
	* Get the pubKeyHash for this key.
	*
	* This is calculated as RIPE160(SHA256([encoded pubkey])) and returned as
	* a byte array.
	*/
	ECKey.prototype.getPubKeyHash = function () {
		if (this.compressed) {
			if (this.pubKeyHashComp) return this.pubKeyHashComp;
			return this.pubKeyHashComp = Dogecoin.Util.sha256ripe160(this.getPub());
		} else {
			if (this.pubKeyHashUncomp) return this.pubKeyHashUncomp;
			return this.pubKeyHashUncomp = Dogecoin.Util.sha256ripe160(this.getPub());
		}
	};

	ECKey.prototype.getDogecoinAddress = function () {
		var hash = this.getPubKeyHash();
		var addr = new Dogecoin.Address(hash);
		return addr;
	};

	/*
	* Takes a public point as a hex string or byte array
	*/
	ECKey.prototype.setPub = function (pub) {
		// byte array
		if (Dogecoin.Util.isArray(pub)) {
			pub = Crypto.util.bytesToHex(pub).toString().toUpperCase();
		}
		var ecPoint = ecparams.getCurve().decodePointHex(pub);
		this.setCompressed(ecPoint.compressed);
		this.pubPoint = ecPoint;
		return this;
	};

	// Sipa Private Key Wallet Import Format 
	ECKey.prototype.getDogecoinWalletImportFormat = function () {
		var bytes = this.getDogecoinPrivateKeyByteArray();
		bytes.unshift(ECKey.privateKeyPrefix); // prepend 0x80 byte
		if (this.compressed) bytes.push(0x01); // append 0x01 byte for compressed format
		var checksum = Crypto.SHA256(Crypto.SHA256(bytes, { asBytes: true }), { asBytes: true });
		bytes = bytes.concat(checksum.slice(0, 4));
		var privWif = Dogecoin.Base58.encode(bytes);
		return privWif;
	};

	// Private Key Hex Format 
	ECKey.prototype.getDogecoinHexFormat = function () {
		return Crypto.util.bytesToHex(this.getDogecoinPrivateKeyByteArray()).toString().toUpperCase();
	};

	// Private Key Base64 Format 
	ECKey.prototype.getDogecoinBase64Format = function () {
		return Crypto.util.bytesToBase64(this.getDogecoinPrivateKeyByteArray());
	};

	ECKey.prototype.getDogecoinPrivateKeyByteArray = function () {
		// Get a copy of private key as a byte array
		var bytes = this.priv.toByteArrayUnsigned();
		// zero pad if private key is less than 32 bytes 
		while (bytes.length < 32) bytes.unshift(0x00);
		return bytes;
	};

	ECKey.prototype.toString = function (format) {
		format = format || "";
		if (format.toString().toLowerCase() == "base64" || format.toString().toLowerCase() == "b64") {
			return this.getDogecoinBase64Format();
		}
		// Wallet Import Format
		else if (format.toString().toLowerCase() == "wif") {
			return this.getDogecoinWalletImportFormat();
		}
		else {
			return this.getDogecoinHexFormat();
		}
	};

	ECKey.prototype.sign = function (hash) {
		return ECDSA.sign(hash, this.priv);
	};

	ECKey.prototype.verify = function (hash, sig) {
		return ECDSA.verify(hash, sig, this.getPub());
	};

	/**
	* Parse a wallet import format private key contained in a string.
	*/
	ECKey.decodeWalletImportFormat = function (privStr) {
		var bytes = Dogecoin.Base58.decode(privStr);
		var hash = bytes.slice(0, 33);
		var checksum = Crypto.SHA256(Crypto.SHA256(hash, { asBytes: true }), { asBytes: true });
		if (checksum[0] != bytes[33] ||
					checksum[1] != bytes[34] ||
					checksum[2] != bytes[35] ||
					checksum[3] != bytes[36]) {
			throw "Checksum validation failed!";
		}
		var version = hash.shift();
		if (version != ECKey.privateKeyPrefix) {
			throw "Version " + version + " not supported!";
		}
		return hash;
	};

	/**
	* Parse a compressed wallet import format private key contained in a string.
	*/
	ECKey.decodeCompressedWalletImportFormat = function (privStr) {
		var bytes = Dogecoin.Base58.decode(privStr);
		var hash = bytes.slice(0, 34);
		var checksum = Crypto.SHA256(Crypto.SHA256(hash, { asBytes: true }), { asBytes: true });
		if (checksum[0] != bytes[34] ||
					checksum[1] != bytes[35] ||
					checksum[2] != bytes[36] ||
					checksum[3] != bytes[37]) {
			throw "Checksum validation failed!";
		}
		var version = hash.shift();
		if (version != ECKey.privateKeyPrefix) {
			throw "Version " + version + " not supported!";
		}
		hash.pop();
		return hash;
	};

	// 64 characters [0-9A-F]
	ECKey.isHexFormat = function (key) {
		key = key.toString();
		return /^[A-Fa-f0-9]{64}$/.test(key);
	};

	// 51 characters base58, always starts with a '5'
	ECKey.isWalletImportFormat = function (key) {
		key = key.toString();
		return (ECKey.privateKeyPrefix == 0x9E) ? (/^6[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{50}$/.test(key)) : false;
	};

	// 52 characters base58
	ECKey.isCompressedWalletImportFormat = function (key) {
		key = key.toString();
		return (ECKey.privateKeyPrefix == 0x9E) ? (/^[Q][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{51}$/.test(key)) : false;
	};

	// 44 characters
	ECKey.isBase64Format = function (key) {
		key = key.toString();
		return (/^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=+\/]{44}$/.test(key));
	};

	// 99 characters, 1=1, if using dice convert 6 to 0
	ECKey.isBase6Format = function (key) {
		key = key.toString();
		return (/^[012345]{99}$/.test(key));
	};

	// 22, 26 or 30 characters, always starts with an 'S'
	ECKey.isMiniFormat = function (key) {
		key = key.toString();
		var validChars22 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{21}$/.test(key);
		var validChars26 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{25}$/.test(key);
		var validChars30 = /^S[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{29}$/.test(key);
		var testBytes = Crypto.SHA256(key + "?", { asBytes: true });

		return ((testBytes[0] === 0x00 || testBytes[0] === 0x01) && (validChars22 || validChars26 || validChars30));
	};

	return ECKey;
})();
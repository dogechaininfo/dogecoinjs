// BigInteger monkey patching
BigInteger.valueOf = nbv;

/**
 * Returns a byte array representation of the big integer.
 *
 * This returns the absolute of the contained value in big endian
 * form. A value of zero results in an empty array.
 */
BigInteger.prototype.toByteArrayUnsigned = function () {
  var ba = this.abs().toByteArray();
  if (ba.length) {
    if (ba[0] == 0) {
      ba = ba.slice(1);
    }
    return ba.map(function (v) {
      return (v < 0) ? v + 256 : v;
    });
  } else {
    // Empty array, nothing to do
    return ba;
  }
};

/**
 * Turns a byte array into a big integer.
 *
 * This function will interpret a byte array as a big integer in big
 * endian notation and ignore leading zeros.
 */
BigInteger.fromByteArrayUnsigned = function (ba) {
  if (!ba.length) {
    return ba.valueOf(0);
  } else if (ba[0] & 0x80) {
    // Prepend a zero so the BigInteger class doesn't mistake this
    // for a negative integer.
    return new BigInteger([0].concat(ba));
  } else {
    return new BigInteger(ba);
  }
};

/**
 * Converts big integer to signed byte representation.
 *
 * The format for this value uses a the most significant bit as a sign
 * bit. If the most significant bit is already occupied by the
 * absolute value, an extra byte is prepended and the sign bit is set
 * there.
 *
 * Examples:
 *
 *      0 =>     0x00
 *      1 =>     0x01
 *     -1 =>     0x81
 *    127 =>     0x7f
 *   -127 =>     0xff
 *    128 =>   0x0080
 *   -128 =>   0x8080
 *    255 =>   0x00ff
 *   -255 =>   0x80ff
 *  16300 =>   0x3fac
 * -16300 =>   0xbfac
 *  62300 => 0x00f35c
 * -62300 => 0x80f35c
 */
BigInteger.prototype.toByteArraySigned = function () {
  var val = this.abs().toByteArrayUnsigned();
  var neg = this.compareTo(BigInteger.ZERO) < 0;

  if (neg) {
    if (val[0] & 0x80) {
      val.unshift(0x80);
    } else {
      val[0] |= 0x80;
    }
  } else {
    if (val[0] & 0x80) {
      val.unshift(0x00);
    }
  }

  return val;
};

/**
 * Parse a signed big integer byte representation.
 *
 * For details on the format please see BigInteger.toByteArraySigned.
 */
BigInteger.fromByteArraySigned = function (ba) {
  // Check for negative value
  if (ba[0] & 0x80) {
    // Remove sign bit
    ba[0] &= 0x7f;

    return BigInteger.fromByteArrayUnsigned(ba).negate();
  } else {
    return BigInteger.fromByteArrayUnsigned(ba);
  }
};

// Console ignore
var names = ["log", "debug", "info", "warn", "error", "assert", "dir",
             "dirxml", "group", "groupEnd", "time", "timeEnd", "count",
             "trace", "profile", "profileEnd"];

if ("undefined" == typeof window.console) window.console = {};
for (var i = 0; i < names.length; ++i)
  if ("undefined" == typeof window.console[names[i]])
    window.console[names[i]] = function() {};

// Dogecoin utility functions
Dogecoin.Util = {
  /**
   * Cross-browser compatibility version of Array.isArray.
   */
  isArray: Array.isArray || function(o)
  {
    return Object.prototype.toString.call(o) === '[object Array]';
  },

  /**
   * Create an array of a certain length filled with a specific value.
   */
  makeFilledArray: function (len, val)
  {
    var array = [];
    var i = 0;
    while (i < len) {
      array[i++] = val;
    }
    return array;
  },

  /**
   * Turn an integer into a "var_int".
   *
   * "var_int" is a variable length integer used by Dogecoin's binary format.
   *
   * Returns a byte array.
   */
  numToVarInt: function (i)
  {
    if (i < 0xfd) {
      // unsigned char
      return [i];
    } else if (i <= 1<<16) {
      // unsigned short (LE)
      return [0xfd, i >>> 8, i & 255];
    } else if (i <= 1<<32) {
      // unsigned int (LE)
      return [0xfe].concat(Crypto.util.wordsToBytes([i]));
    } else {
      // unsigned long long (LE)
      return [0xff].concat(Crypto.util.wordsToBytes([i >>> 32, i]));
    }
  },

  /**
   * Parse a Dogecoin value byte array, returning a BigInteger.
   */
  valueToBigInt: function (valueBuffer)
  {
    if (valueBuffer instanceof BigInteger) return valueBuffer;

    // Prepend zero byte to prevent interpretation as negative integer
    return BigInteger.fromByteArrayUnsigned(valueBuffer);
  },

  /**
   * Format a Dogecoin value as a string.
   *
   * Takes a BigInteger or byte-array and returns that amount of Dogecoins in a
   * nice standard formatting.
   *
   * Examples:
   * 12.3555
   * 0.1234
   * 900.99998888
   * 34.00
   */
  formatValue: function (valueBuffer) {
    var value = this.valueToBigInt(valueBuffer).toString();
    var integerPart = value.length > 8 ? value.substr(0, value.length-8) : '0';
    var decimalPart = value.length > 8 ? value.substr(value.length-8) : value;
    while (decimalPart.length < 8) decimalPart = "0"+decimalPart;
    decimalPart = decimalPart.replace(/0*$/, '');
    while (decimalPart.length < 2) decimalPart += "0";
    return integerPart+"."+decimalPart;
  },

  /**
   * Parse a floating point string as a Dogecoin value.
   *
   * Keep in mind that parsing user input is messy. You should always display
   * the parsed value back to the user to make sure we understood his input
   * correctly.
   */
  parseValue: function (valueString) {
    // TODO: Detect other number formats (e.g. comma as decimal separator)
    var valueComp = valueString.split('.');
    var integralPart = valueComp[0];
    var fractionalPart = valueComp[1] || "0";
    while (fractionalPart.length < 8) fractionalPart += "0";
    fractionalPart = fractionalPart.replace(/^0+/g, '');
    var value = BigInteger.valueOf(parseInt(integralPart));
    value = value.multiply(BigInteger.valueOf(100000000));
    value = value.add(BigInteger.valueOf(parseInt(fractionalPart)));
    return value;
  },

  /**
   * Calculate RIPEMD160(SHA256(data)).
   *
   * Takes an arbitrary byte array as inputs and returns the hash as a byte
   * array.
   */
  sha256ripe160: function (data) {
    return Crypto.RIPEMD160(Crypto.SHA256(data, {asBytes: true}), {asBytes: true});
  },
  
  generateGUID: function() {
    var p1 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p2 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p3 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p4 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p5 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p6 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p7 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    var p8 = (((1+Math.random())*0x10000)|0).toString(16).substring(1);
    
    guid = (p1 + p2 + "-" + p3 + "-4" + p4.substr(0,3) + "-" + p5 + "-" + p6 + p7 + p8).toLowerCase();
    
    return guid;
  },
  
  toBBE: function(sendTx) {
        //serialize to Bitcoin Block Explorer format
        var buf = sendTx.serialize();
        var hash = Crypto.SHA256(Crypto.SHA256(buf, {asBytes: true}), {asBytes: true});

        var r = {};
        r['hash'] = Crypto.util.bytesToHex(hash.reverse());
        r['ver'] = sendTx.version;
        r['vin_sz'] = sendTx.ins.length;
        r['vout_sz'] = sendTx.outs.length;
        r['lock_time'] = sendTx.lock_time;
        r['size'] = buf.length;
        r['in'] = []
        r['out'] = []

        for (var i = 0; i < sendTx.ins.length; i++) {
            var txin = sendTx.ins[i];
            var hash = Crypto.util.base64ToBytes(txin.outpoint.hash);
            var n = txin.outpoint.index;
            var prev_out = {'hash': Crypto.util.bytesToHex(hash.reverse()), 'n': n};

            if (n == 4294967295) {
                var cb = Crypto.util.bytesToHex(txin.script.buffer);
                r['in'].push({'prev_out': prev_out, 'coinbase' : cb});
            } else {
                var ss = dumpScript(txin.script);
                r['in'].push({'prev_out': prev_out, 'scriptSig' : ss});
            }
        }

        for (var i = 0; i < sendTx.outs.length; i++) {
            var txout = sendTx.outs[i];
            var bytes = txout.value.slice(0);
            var fval = parseFloat(Bitcoin.Util.formatValue(bytes.reverse()));
            var value = fval.toFixed(8);
            var spk = dumpScript(txout.script);
            r['out'].push({'value' : value, 'scriptPubKey': spk});
        }

        return JSON.stringify(r, null, 4);
    },
    
    doubleSHA256: function(data) {
        return Crypto.SHA256(Crypto.SHA256(data, { asBytes: true }), { asBytes: true });
    },
    
    encryptPrivateKeyToBIP38: function(key, password, callback) {
        var privKey = new Dogecoin.ECKey(key);
        var privKeyBytes = privKey.getDogecoinPrivateKeyByteArray();
        var address = privKey.getDogecoinAddress();
        var compressed = privKey.compressed;
        
        // Compute sha256(sha256(address)) and take first 4 bytes
		var salt = Dogecoin.Util.doubleSHA256(address).slice(0, 4);
        
        // Derive key using scrypt
		var aesOptions = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };
        
        Crypto_scrypt(password, salt, 16384, 8, 8, 64, function (derivedBytes) {
			for (var i = 0; i < 32; ++i) {
				privKeyBytes[i] ^= derivedBytes[i];
			}

			// 0x01 0x42 + flagbyte + salt + encryptedhalf1 + encryptedhalf2
			var flagByte = compressed ? 0xe0 : 0xc0;
			var encryptedKey = [0x01, 0x42, flagByte].concat(salt);
			encryptedKey = encryptedKey.concat(Crypto.AES.encrypt(privKeyBytes, derivedBytes.slice(32), aesOptions));
			encryptedKey = encryptedKey.concat(Dogecoin.Util.doubleSHA256(encryptedKey).slice(0, 4));
			callback(Dogecoin.Base58.encode(encryptedKey));
		});
    },
    
    decryptPrivateKeyFromBIP38: function(base58Encrypted, passphrase, callback) {
        var hex;
        
		try {
			hex = Dogecoin.Base58.decode(base58Encrypted);
		} catch (e) {
			callback(new Error("Invalid private key"));
			return;
		}

		// 43 bytes: 2 bytes prefix, 37 bytes payload, 4 bytes checksum
		if (hex.length != 43) {
			callback(new Error("Invalid private key"));
			return;
		}
        
		// first byte is always 0x01 
		else if (hex[0] != 0x01) {
			callback(new Error("Invalid private key"));
			return;
		}

		var expChecksum = hex.slice(-4);
		hex = hex.slice(0, -4);
		var checksum = Dogecoin.Util.doubleSHA256(hex);
		if (checksum[0] != expChecksum[0] || checksum[1] != expChecksum[1] || checksum[2] != expChecksum[2] || checksum[3] != expChecksum[3]) {
			callback(new Error("Invalid private key"));
			return;
		}

		var isCompPoint = false;
		var isECMult = false;
		var hasLotSeq = false;
		// second byte for non-EC-multiplied key
		if (hex[1] == 0x42) {
			// key should use compression
			if (hex[2] == 0xe0) {
				isCompPoint = true;
			}
			// key should NOT use compression
			else if (hex[2] != 0xc0) {
				callback(new Error("Invalid private key"));
				return;
			}
		}
		// second byte for EC-multiplied key 
		else if (hex[1] == 0x43) {
			isECMult = true;
			isCompPoint = (hex[2] & 0x20) != 0;
			hasLotSeq = (hex[2] & 0x04) != 0;
			if ((hex[2] & 0x24) != hex[2]) {
				callback(new Error("Invalid private key"));
				return;
			}
		}
		else {
			callback(new Error("Invalid private key"));
			return;
		}

		var decrypted;
		var AES_opts = { mode: new Crypto.mode.ECB(Crypto.pad.NoPadding), asBytes: true };

		var verifyHashAndReturn = function () {
			var tmpkey = new Dogecoin.ECKey(decrypted); // decrypted using closure
			var base58AddrText = tmpkey.setCompressed(isCompPoint).getDogecoinAddress(); // isCompPoint using closure
			checksum = Dogecoin.Util.doubleSHA256(base58AddrText); // checksum using closure

			if (checksum[0] != hex[3] || checksum[1] != hex[4] || checksum[2] != hex[5] || checksum[3] != hex[6]) {
				callback(new Error("Invalid private key")); // callback using closure
				return;
			}
			callback(tmpkey); // callback using closure
		};

		if (!isECMult) {
			var addresshash = hex.slice(3, 7);
			Crypto_scrypt(passphrase, addresshash, 16384, 8, 8, 64, function (derivedBytes) {
				var k = derivedBytes.slice(32, 32 + 32);
				decrypted = Crypto.AES.decrypt(hex.slice(7, 7 + 32), k, AES_opts);
				for (var x = 0; x < 32; x++) decrypted[x] ^= derivedBytes[x];
				verifyHashAndReturn(); //TODO: pass in 'decrypted' as a param
			});
		}
		else {
			var ownerentropy = hex.slice(7, 7 + 8);
			var ownersalt = !hasLotSeq ? ownerentropy : ownerentropy.slice(0, 4);
			Crypto_scrypt(passphrase, ownersalt, 16384, 8, 8, 32, function (prefactorA) {
				var passfactor;
				if (!hasLotSeq) { // hasLotSeq using closure
					passfactor = prefactorA;
				} else {
					var prefactorB = prefactorA.concat(ownerentropy); // ownerentropy using closure
					passfactor = Dogecoin.Util.doubleSHA256(prefactorB);
				}
				var kp = new Dogecoin.ECKey(passfactor);
				var passpoint = kp.setCompressed(true).getPub();

				var encryptedpart2 = hex.slice(23, 23 + 16);

				var addresshashplusownerentropy = hex.slice(3, 3 + 12);
				Crypto_scrypt(passpoint, addresshashplusownerentropy, 1024, 1, 1, 64, function (derived) {
					var k = derived.slice(32);

					var unencryptedpart2 = Crypto.AES.decrypt(encryptedpart2, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart2[i] ^= derived[i + 16]; }

					var encryptedpart1 = hex.slice(15, 15 + 8).concat(unencryptedpart2.slice(0, 0 + 8));
					var unencryptedpart1 = Crypto.AES.decrypt(encryptedpart1, k, AES_opts);
					for (var i = 0; i < 16; i++) { unencryptedpart1[i] ^= derived[i]; }

					var seedb = unencryptedpart1.slice(0, 0 + 16).concat(unencryptedpart2.slice(8, 8 + 8));

					var factorb = Dogecoin.Util.doubleSHA256(seedb);

					var ps = EllipticCurve.getSECCurveByName("secp256k1");
					var privateKey = BigInteger.fromByteArrayUnsigned(passfactor).multiply(BigInteger.fromByteArrayUnsigned(factorb)).remainder(ps.getN());

					decrypted = privateKey.toByteArrayUnsigned();
					verifyHashAndReturn();
				});
			});
		}
    }
};

for (var i in Crypto.util) {
  if (Crypto.util.hasOwnProperty(i)) {
    Dogecoin.Util[i] = Crypto.util[i];
  }
}

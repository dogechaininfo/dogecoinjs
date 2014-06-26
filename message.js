/**
 * Implements Dogecoin's feature for signing arbitrary messages.
 */
Dogecoin.Message = (function () {
    var Message = {};

    Message.magicPrefix = "Dogecoin Signed Message:\n";

    Message.makeMagicMessage = function (message) {
        var magicBytes = Crypto.charenc.UTF8.stringToBytes(Message.magicPrefix);
        var messageBytes = Crypto.charenc.UTF8.stringToBytes(message);

        var buffer = [];
        buffer = buffer.concat(Dogecoin.Util.numToVarInt(magicBytes.length));
        buffer = buffer.concat(magicBytes);
        buffer = buffer.concat(Dogecoin.Util.numToVarInt(messageBytes.length));
        buffer = buffer.concat(messageBytes);

        return buffer;
    };

    Message.getHash = function (message) {
        var buffer = Message.makeMagicMessage(message);
        return Crypto.SHA256(Crypto.SHA256(buffer, {asBytes: true}), {asBytes: true});
    };

    Message.signMessage = function (key, message) {
        var hash = Message.getHash(message);
        var signature = key.sign(hash);
        var obj = Dogecoin.ECDSA.parseSig(signature);
        
        var address = new Dogecoin.Address(key.getPubKeyHash());
        
        var sequence = [0];
        sequence = sequence.concat(obj.r.toByteArrayUnsigned());
        sequence = sequence.concat(obj.s.toByteArrayUnsigned());
        
        for (var i = 0; i < 4; i++) {
            var nV = 27 + i;
            
            sequence[0] = nV;
            var sig = Crypto.util.bytesToBase64(sequence);
            if (Message.verifyMessage(sig, message) == address)
                return sig;
        }
    };

    Message.verifyMessage = function (signature, message) {
        try {
            var sig = Crypto.util.base64ToBytes(signature);
        } catch(err) {
            return false;
        }

        if (sig.length != 65)
            return false;

        // extract r,s from signature
        var r = BigInteger.fromByteArrayUnsigned(sig.slice(1,1+32));
        var s = BigInteger.fromByteArrayUnsigned(sig.slice(33,33+32));

        // get recid
        var compressed = false;
        var nV = sig[0];
        if (nV < 27 || nV >= 35)
            return false;
        if (nV >= 31) {
            compressed = true;
            nV -= 4;
        }
        var recid = BigInteger.valueOf(nV - 27);

        var ecparams = getSECCurveByName("secp256k1");
        var curve = ecparams.getCurve();
        var a = curve.getA().toBigInteger();
        var b = curve.getB().toBigInteger();
        var p = curve.getQ();
        var G = ecparams.getG();
        var order = ecparams.getN();

        var x = r.add(order.multiply(recid.divide(BigInteger.valueOf(2))));
        var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
        var beta = alpha.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        var y = beta.subtract(recid).isEven() ? beta : p.subtract(beta);

        var R = new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
        var e = BigInteger.fromByteArrayUnsigned(Message.getHash(message));
        var minus_e = e.negate().mod(order);
        var inv_r = r.modInverse(order);
        var Q = (R.multiply(s).add(G.multiply(minus_e))).multiply(inv_r);

        var public_key = Q.getEncoded(compressed);
        var addr = new Dogecoin.Address(Dogecoin.Util.sha256ripe160(public_key));
        
        return addr.toString();
    };


    return Message;
})();
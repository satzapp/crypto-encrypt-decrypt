"use strict";
const crypto = require('crypto');

class encryptHash {

    encrypt(data) {
        var cipher = crypto.createCipher('aes-256-cbc', 'encryptionKey');
        var crypted = cipher.update(data, 'utf-8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }

    decrypt(data) {
        var decipher = crypto.createDecipher('aes-256-cbc', 'encryptionKey');
        var decrypted = decipher.update(data, 'hex', 'utf-8');
        decrypted += decipher.final('utf-8');
        return decrypted;
    }
}

module.exports = new encryptHash();
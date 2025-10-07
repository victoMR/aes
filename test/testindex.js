import crypto from "crypto";

function hash(mensaje) {
    const hash = crypto.createHash('sha512');
    hash.update(mensaje);
    return hash.digest('hex');
}


module.exports = hash;
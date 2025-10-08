const crypto = require('crypto');

function hash(message) {
  const hash = crypto.createHash('sha512');
  hash.update(message);
  return hash.digest('hex');
}

module.exports = {
  hash,
};

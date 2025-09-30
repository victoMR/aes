var express = require('express');
var router = express.Router();
const crypto = require('crypto');
router.use(express.json());
const key = crypto.randomBytes(32); // Genera una clave de 32 bytes (256 bits)
const iv = crypto.randomBytes(16);  // Genera un IV de 16 bytes

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.post('/encrypt', (req, res) => {
  const data  = req.body
  const algorithm = 'aes-256-cbc';

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(data.mensaje, 'utf-8', 'hex');
  encryptedData += cipher.final('hex');

  console.log('Mensaje cifrado (hex):', encryptedData);
  res.json({
    'mensaje-cifrado': encryptedData
  })
})

router.post('/decrypt', (req, res) => {
  const encryptedData = req.body
  const algorithm = 'aes-256-cbc';
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decryptedData = decipher.update(encryptedData.mensaje, 'hex', 'utf-8');
  decryptedData += decipher.final('utf-8');

  res.json({
    'mensaje-decifrado': decryptedData
  })
})







router.get('/getkeys', (req, res) => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  res.json({
    'privateKey': privateKey.toString('hex'),
    'publicKey': publicKey.toString('hex'),
  })
});

router.post('/encrypt-ecc', (req, res) => {
  const data  = req.body
  const sign =  crypto.createSign('sha256');
  sign.write(data.mensaje);
  sign.end();
  var signature = sign.sign(data.privateKey, 'hex');

  res.json({
    'mensaje-cifrado': signature.toString('hex')
  })
});


router.post('/verify-ecc', (req, res) => {
  const data = req.body

  const verify = crypto.createVerify('sha256');
  verify.write(data.mensaje);
  verify.end();

  res.json({


    'verify': verify.verify(data.publicKey, data.signature, 'hex')
  });
});

module.exports = router;

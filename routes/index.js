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


module.exports = router;

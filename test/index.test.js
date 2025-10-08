const index = require('./testindex');

test('Filter even numbers', () => {
  const message = "constraseña"
  const hashedMessage = index.hash(message);
  expect(hashedMessage).toBe('15b0eac672f0e1e243bec1362214c27a27be82691f5e5e865cb954555edce504be1c2b36de08c3081bf26362f877469728617f0797a6cf4ab81f352262c0dfa2');
});

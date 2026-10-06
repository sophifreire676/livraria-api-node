require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('ERRO: defina JWT_SECRET no arquivo .env (veja .env.example).');
  process.exit(1);
}

module.exports = {
  JWT_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
  BCRYPT_ROUNDS: Number(process.env.BCRYPT_ROUNDS) || 10,
  PORT: Number(process.env.PORT) || 3000
};

const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config');

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const [esquema, token] = authHeader ? authHeader.split(' ') : [];

  if (!authHeader || !/^Bearer$/i.test(esquema) || !token) {
    return res.status(401).json({ erro: "Token de autenticação não fornecido ou mal formatado (use: Authorization: Bearer <token>)." });
  }

  try {
    // Fixar o algoritmo impede ataques de troca de algoritmo (ex.: alg "none").
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.usuario = { id: Number(payload.sub), nome: payload.nome, role: payload.role };
    next();
  } catch (err) {
    const mensagem = err.name === 'TokenExpiredError' ? "Token expirado." : "Token inválido.";
    return res.status(401).json({ erro: mensagem });
  }
}

function exigirRole(...rolesPermitidas) {
  return (req, res, next) => {
    if (!req.usuario || !rolesPermitidas.includes(req.usuario.role)) {
      return res.status(403).json({ erro: `Acesso proibido: privilégio de ${rolesPermitidas.join(' ou ')} exigido.` });
    }
    next();
  };
}

module.exports = { autenticarToken, exigirRole };

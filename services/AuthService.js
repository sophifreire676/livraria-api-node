const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const repository = require('../repositories/LivrariaRepository');
const { JWT_SECRET, JWT_EXPIRES_IN, BCRYPT_ROUNDS } = require('../config');

// Hash descartável: usado para gastar o mesmo tempo de CPU quando o e-mail não existe,
// evitando que o tempo de resposta revele quais e-mails estão cadastrados.
const HASH_FALSO = bcrypt.hashSync('senha-descartavel', BCRYPT_ROUNDS);

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class AuthService {
  async registrar({ nome, email, senha } = {}) {
    if (!nome || !email || !senha) {
      throw { status: 400, message: "Campos obrigatórios ausentes: nome, email ou senha." };
    }
    if (typeof nome !== 'string' || typeof email !== 'string' || typeof senha !== 'string') {
      throw { status: 400, message: "Campos nome, email e senha devem ser texto." };
    }
    if (!EMAIL_REGEX.test(email.trim())) {
      throw { status: 400, message: "E-mail inválido." };
    }
    if (senha.length < 6) {
      throw { status: 400, message: "A senha deve ter no mínimo 6 caracteres." };
    }

    const emailNormalizado = email.trim().toLowerCase();
    if (repository.buscarUsuarioPorEmail(emailNormalizado)) {
      throw { status: 409, message: "E-mail já cadastrado no sistema." };
    }

    // BCrypt gera o salt aleatório e o embute no hash; BCRYPT_ROUNDS é o work factor.
    const senha_hash = await bcrypt.hash(senha, BCRYPT_ROUNDS);

    // Cadastro público SEMPRE cria USER: aceitar "role" do corpo permitiria
    // que qualquer pessoa se cadastrasse como ADMIN (escalada de privilégio).
    const novoUsuario = repository.salvarUsuario({
      nome: nome.trim(),
      email: emailNormalizado,
      senha_hash,
      role: "USER"
    });

    const { senha_hash: _, ...usuarioRetorno } = novoUsuario;
    return usuarioRetorno;
  }

  async login({ email, senha } = {}) {
    if (!email || !senha) {
      throw { status: 400, message: "E-mail e senha são obrigatórios." };
    }
    if (typeof email !== 'string' || typeof senha !== 'string') {
      throw { status: 400, message: "E-mail e senha devem ser texto." };
    }

    const usuario = repository.buscarUsuarioPorEmail(email);
    const senhaConfere = await bcrypt.compare(senha, usuario ? usuario.senha_hash : HASH_FALSO);

    // Mesma mensagem para e-mail inexistente e senha errada.
    if (!usuario || !senhaConfere) {
      throw { status: 401, message: "Credenciais inválidas." };
    }

    const token = jwt.sign(
      { nome: usuario.nome, role: usuario.role },
      JWT_SECRET,
      { subject: String(usuario.id), expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' }
    );

    return {
      usuario: { id: usuario.id, nome: usuario.nome, role: usuario.role },
      token
    };
  }
}

module.exports = new AuthService();

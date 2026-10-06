# Livraria API (Node + Express) — Camada de Segurança

API RESTful de Livros e Autores com autenticação **JWT**, senhas com **BCrypt** e controle de acesso por perfil (**RBAC**).

## Como rodar
```bash
npm install
cp .env.example .env   # troque JWT_SECRET por um valor longo e aleatório
npm start              # http://localhost:3000
```
Abra `index.html` no navegador para o painel de testes.

## Credenciais de teste
| Perfil | E-mail | Senha |
|---|---|---|
| ADMIN | admin@livraria.com | admin123 |
| USER | leitor@gmail.com | leitor123 |

## Segurança implementada
- **BCrypt** (`bcryptjs`): hash com salt aleatório embutido e work factor configurável (`BCRYPT_ROUNDS`, padrão 10). Nenhuma senha em texto puro é gravada ou retornada.
- **JWT stateless** (`jsonwebtoken`): emitido no login (HS256, expira em `JWT_EXPIRES_IN`, padrão 1h), com `sub`, `nome` e `role`. Validado em `middlewares/authMiddleware.js` a cada requisição via `Authorization: Bearer <token>`; o algoritmo é fixado em HS256 (bloqueia tokens `alg: none`).
- **RBAC**: `autenticarToken` (401 se ausente/inválido/expirado) + `exigirRole('ADMIN')` (403 se o perfil não basta).
- Cadastro público **sempre cria USER**; o campo `role` enviado no corpo é ignorado (evita escalada de privilégio).
- Login devolve a mesma mensagem (401) para e-mail inexistente e senha errada, e gasta o mesmo tempo de CPU nos dois casos.
- Segredo JWT vem do `.env` (ignorado pelo git); a API não sobe sem ele.

## Matriz de permissões
| Método | Rota | Acesso | Sucesso | Falha |
|---|---|---|---|---|
| GET | /api/v1/livros | Público | 200 | — |
| GET | /api/v1/livros/:id | Público | 200 | — |
| POST | /api/v1/auth/register | Público | 201 | 400/409 |
| POST | /api/v1/auth/login | Público | 200 | 401 |
| POST | /api/v1/livros/:id/comentarios | USER ou ADMIN | 201 | 401 |
| POST | /api/v1/autores | ADMIN | 201 | 401 / 403 |
| POST | /api/v1/livros | ADMIN | 201 | 401 / 403 |

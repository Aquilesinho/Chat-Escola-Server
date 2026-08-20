# Chat Escola — Servidor

Servidor inicial do Chat Escola usando:

- Python
- Flask
- SQLite
- Flask-CORS
- Pillow

## Instalar

No terminal:

```powershell
pip install -r requirements.txt
```

## Executar

```powershell
python server.py
```

O servidor ficará em:

http://127.0.0.1:5000

## Cadastro

POST:

`/api/register`

Formato: `multipart/form-data`

Campos:

- `nome`
- `senha`
- `imagem` (opcional)

Resposta:

```json
{
    "ok": true,
    "mensagem": "Conta criada com sucesso.",
    "token": "...",
    "usuario": {
        "id": "...",
        "nome": "Aquiles",
        "imagem": "..."
    }
}
```

## Login

POST:

`/api/login`

JSON:

```json
{
    "nome": "Aquiles",
    "senha": "minha senha"
}
```

## Usuário logado

GET:

`/api/me`

Header:

`Authorization: Bearer SEU_TOKEN`

## Logout

POST:

`/api/logout`

Header:

`Authorization: Bearer SEU_TOKEN`

## Imagens

Depois do cadastro, uma imagem pode ser acessada em:

`/uploads/NOME_DO_ARQUIVO`

## Segurança

A senha nunca é salva diretamente no banco.

Ela é transformada em hash usando `scrypt`.

O token de sessão é aleatório e também não contém a senha.

Antes do lançamento oficial:

- usar HTTPS;
- configurar CORS apenas para o domínio oficial;
- desligar `debug=True`;
- colocar o servidor em uma hospedagem própria;
- adicionar limite de tentativas de login;
- fazer backup do banco;
- adicionar recuperação de senha;
- adicionar verificação de conta, se necessário.
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import sqlite3, os, uuid, secrets, io
from functools import wraps
from datetime import datetime, timezone


BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'chat_escola.db')
UPLOADS = os.path.join(BASE, 'uploads')
MAX_FILE = 5 * 1024 * 1024
CATEGORIES = {'principal', 'livro', 'materia', 'capitulo'}
os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 7 * 1024 * 1024
CORS(app)


def now():
    return datetime.now(timezone.utc).isoformat()


def uid():
    return str(uuid.uuid4())


def db():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA journal_mode=WAL')
    return c


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id TEXT PRIMARY KEY,
        nome TEXT NOT NULL COLLATE NOCASE UNIQUE,
        senha_hash TEXT NOT NULL,
        imagem TEXT,
        criado_em TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessoes (
        token TEXT PRIMARY KEY,
        usuario_id TEXT NOT NULL,
        criado_em TEXT NOT NULL,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS grupos (
        id TEXT PRIMARY KEY,
        nome TEXT NOT NULL COLLATE NOCASE UNIQUE,
        senha_hash TEXT NOT NULL,
        criado_por TEXT,
        criado_em TEXT NOT NULL,
        FOREIGN KEY(criado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS usuario_grupos (
        usuario_id TEXT NOT NULL,
        grupo_id TEXT NOT NULL,
        entrou_em TEXT NOT NULL,
        PRIMARY KEY(usuario_id, grupo_id),
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        FOREIGN KEY(grupo_id) REFERENCES grupos(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS series (
        id TEXT PRIMARY KEY,
        grupo_id TEXT NOT NULL,
        nome TEXT NOT NULL COLLATE NOCASE,
        senha_hash TEXT NOT NULL,
        criado_por TEXT,
        criado_em TEXT NOT NULL,
        UNIQUE(grupo_id, nome),
        FOREIGN KEY(grupo_id) REFERENCES grupos(id) ON DELETE CASCADE,
        FOREIGN KEY(criado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS usuario_series (
        usuario_id TEXT NOT NULL,
        serie_id TEXT NOT NULL,
        entrou_em TEXT NOT NULL,
        PRIMARY KEY(usuario_id, serie_id),
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        FOREIGN KEY(serie_id) REFERENCES series(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS livros (
        id TEXT PRIMARY KEY,
        serie_id TEXT NOT NULL,
        nome TEXT NOT NULL,
        numero INTEGER,
        criado_por TEXT,
        criado_em TEXT NOT NULL,
        UNIQUE(serie_id, nome),
        FOREIGN KEY(serie_id) REFERENCES series(id) ON DELETE CASCADE,
        FOREIGN KEY(criado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS materias (
        id TEXT PRIMARY KEY,
        livro_id TEXT NOT NULL,
        nome TEXT NOT NULL,
        criado_por TEXT,
        criado_em TEXT NOT NULL,
        UNIQUE(livro_id, nome),
        FOREIGN KEY(livro_id) REFERENCES livros(id) ON DELETE CASCADE,
        FOREIGN KEY(criado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS capitulos (
        id TEXT PRIMARY KEY,
        materia_id TEXT NOT NULL,
        numero INTEGER NOT NULL,
        nome TEXT,
        criado_por TEXT,
        criado_em TEXT NOT NULL,
        UNIQUE(materia_id, numero),
        FOREIGN KEY(materia_id) REFERENCES materias(id) ON DELETE CASCADE,
        FOREIGN KEY(criado_por) REFERENCES usuarios(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS resumos (
        id TEXT PRIMARY KEY,
        capitulo_id TEXT NOT NULL,
        usuario_id TEXT NOT NULL,
        titulo TEXT,
        texto TEXT NOT NULL,
        arquivo TEXT,
        imagem TEXT,
        criado_em TEXT NOT NULL,
        atualizado_em TEXT NOT NULL,
        FOREIGN KEY(capitulo_id) REFERENCES capitulos(id) ON DELETE CASCADE,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS mensagens (
        id TEXT PRIMARY KEY,
        usuario_id TEXT NOT NULL,
        categoria TEXT NOT NULL CHECK(categoria IN ('principal','livro','materia','capitulo')),
        grupo_id TEXT NOT NULL,
        serie_id TEXT NOT NULL,
        livro_id TEXT,
        materia_id TEXT,
        capitulo_id TEXT,
        texto TEXT,
        imagem TEXT,
        arquivo TEXT,
        criado_em TEXT NOT NULL,
        FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
        FOREIGN KEY(grupo_id) REFERENCES grupos(id) ON DELETE CASCADE,
        FOREIGN KEY(serie_id) REFERENCES series(id) ON DELETE CASCADE,
        FOREIGN KEY(livro_id) REFERENCES livros(id) ON DELETE CASCADE,
        FOREIGN KEY(materia_id) REFERENCES materias(id) ON DELETE CASCADE,
        FOREIGN KEY(capitulo_id) REFERENCES capitulos(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_msg_principal ON mensagens(grupo_id, serie_id, criado_em);
    CREATE INDEX IF NOT EXISTS idx_msg_livro ON mensagens(livro_id, criado_em);
    CREATE INDEX IF NOT EXISTS idx_msg_materia ON mensagens(materia_id, criado_em);
    CREATE INDEX IF NOT EXISTS idx_msg_capitulo ON mensagens(capitulo_id, criado_em);
    CREATE INDEX IF NOT EXISTS idx_resumos_capitulo ON resumos(capitulo_id, criado_em);
    ''')
    # Migração: versões antigas do banco não tinham idioma.
    colunas = {
        row['name']
        for row in c.execute("PRAGMA table_info(usuarios)").fetchall()
    }

    if 'idioma' not in colunas:
        c.execute(
            "ALTER TABLE usuarios ADD COLUMN idioma TEXT NOT NULL DEFAULT 'en'"
        )

    c.commit()
    c.close()


init_db()


def ok(**data):
    return jsonify({'ok': True, **data})


def bad(message, code=400):
    return jsonify({'ok': False, 'erro': message}), code


def token():
    h = request.headers.get('Authorization', '')
    return h[7:].strip() if h.startswith('Bearer ') else None


def current_user():
    t = token()
    if not t:
        return None
    c = db()
    u = c.execute('''SELECT usuarios.* FROM usuarios JOIN sessoes
                     ON sessoes.usuario_id=usuarios.id WHERE sessoes.token=?''', (t,)).fetchone()
    c.close()
    return u


def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        u = current_user()
        if not u:
            return bad('Você precisa estar logado.', 401)
        return fn(u, *args, **kwargs)
    return wrap


def user_json(u):
    return {
        'id': u['id'],
        'nome': u['nome'],
        'imagem': u['imagem'],
        'idioma': u['idioma'] if 'idioma' in u.keys() else 'en'
    }


def hash_password(s):
    return generate_password_hash(s, method='scrypt')


def save_image(f, prefix):
    if not f or not f.filename:
        return None, None
    raw = f.read(MAX_FILE + 1)
    f.seek(0)
    if len(raw) > MAX_FILE:
        return None, 'A imagem precisa ter no máximo 5 MB.'
    try:
        im = Image.open(io.BytesIO(raw))
        fmt = im.format
        if fmt not in {'PNG', 'JPEG', 'WEBP'}:
            return None, 'Formato de imagem inválido.'
        im.verify()
        f.seek(0)
        im = Image.open(f)
        if fmt == 'JPEG':
            im = im.convert('RGB')
        if im.width > 1600 or im.height > 1600:
            im.thumbnail((1600, 1600))
        ext = {'PNG': 'png', 'JPEG': 'jpg', 'WEBP': 'webp'}[fmt]
        name = f'{prefix}_{secrets.token_hex(8)}.{ext}'
        im.save(os.path.join(UPLOADS, name), format=fmt, optimize=True)
        return name, None
    except Exception:
        return None, 'A imagem enviada é inválida.'


def save_file(f, prefix):
    if not f or not f.filename:
        return None, None
    raw = f.read(MAX_FILE + 1)
    f.seek(0)
    if len(raw) > MAX_FILE:
        return None, 'O arquivo precisa ter no máximo 5 MB.'
    name = os.path.basename(f.filename).replace(' ', '_')
    if not name or name in {'.', '..'}:
        return None, 'Nome de arquivo inválido.'
    name = f'{prefix}_{secrets.token_hex(8)}_{name}'
    try:
        f.save(os.path.join(UPLOADS, name))
        return name, None
    except Exception:
        return None, 'Não foi possível salvar o arquivo.'


def member(c, user_id, table, column, value):
    return c.execute(f'SELECT 1 FROM {table} WHERE usuario_id=? AND {column}=?', (user_id, value)).fetchone() is not None


def serie_of(c, serie_id):
    return c.execute('SELECT * FROM series WHERE id=?', (serie_id,)).fetchone()


def validate_chat(c, user_id, category, group_id, serie_id, book_id=None, subject_id=None, chapter_id=None):
    if category not in {'principal', 'livro', 'materia', 'capitulo'}:
        return False, 'Categoria inválida.'
    s = serie_of(c, serie_id)
    if not s or s['grupo_id'] != group_id:
        return False, 'A série não pertence ao grupo informado.'
    if not member(c, user_id, 'usuario_grupos', 'grupo_id', group_id):
        return False, 'Você não está nesse grupo.'
    if not member(c, user_id, 'usuario_series', 'serie_id', serie_id):
        return False, 'Você não está nessa série.'
    if category == 'principal':
        if book_id or subject_id or chapter_id:
            return False, 'Chat principal não usa livro, matéria ou capítulo.'
    elif category == 'livro':
        if not book_id:
            return False, 'O chat de livro precisa de um livro.'
        if not c.execute('SELECT 1 FROM livros WHERE id=? AND serie_id=?', (book_id, serie_id)).fetchone():
            return False, 'O livro não pertence à série.'
        if subject_id or chapter_id:
            return False, 'Chat de livro não usa matéria ou capítulo.'
    elif category == 'materia':
        if not subject_id:
            return False, 'O chat de matéria precisa de uma matéria.'
        if not c.execute('''SELECT 1 FROM materias JOIN livros ON livros.id=materias.livro_id
                            WHERE materias.id=? AND livros.serie_id=?''', (subject_id, serie_id)).fetchone():
            return False, 'A matéria não pertence à série.'
        if chapter_id:
            return False, 'Chat de matéria não usa capítulo.'
    else:
        if not chapter_id:
            return False, 'O chat de capítulo precisa de um capítulo.'
        if not c.execute('''SELECT 1 FROM capitulos JOIN materias ON materias.id=capitulos.materia_id
                            JOIN livros ON livros.id=materias.livro_id
                            WHERE capitulos.id=? AND livros.serie_id=?''', (chapter_id, serie_id)).fetchone():
            return False, 'O capítulo não pertence à série.'
    return True, None


@app.get('/')
def root():
    return ok(nome='Chat Escola API', versao='2.1.0', status='online')


@app.get('/api/status')
def status():
    c = db()
    out = {}
    for table in ('usuarios', 'grupos', 'series', 'livros', 'materias', 'capitulos', 'mensagens', 'resumos'):
        out[table] = c.execute(f'SELECT COUNT(*) n FROM {table}').fetchone()['n']
    c.close()
    return ok(servidor='online', banco=out)


@app.post('/api/register')
def register():
    nome = request.form.get('nome', '').strip()
    senha = request.form.get('senha', '')
    if not 2 <= len(nome) <= 30:
        return bad('O nome precisa ter entre 2 e 30 caracteres.')
    if not 6 <= len(senha) <= 200:
        return bad('A senha precisa ter entre 6 e 200 caracteres.')
    user_id = uid()
    image = request.files.get('imagem')
    image_name, problem = save_image(image, user_id)
    if problem:
        return bad(problem)
    c = db()
    try:
        c.execute('INSERT INTO usuarios VALUES (?,?,?,?,?)', (user_id, nome, hash_password(senha), image_name, now()))
        c.commit()
    except sqlite3.IntegrityError:
        c.close()
        if image_name and os.path.exists(os.path.join(UPLOADS, image_name)):
            os.remove(os.path.join(UPLOADS, image_name))
        return bad('Esse nome de usuário já está em uso.', 409)
    u = c.execute('SELECT * FROM usuarios WHERE id=?', (user_id,)).fetchone()
    t = secrets.token_urlsafe(64)
    c.execute('INSERT INTO sessoes VALUES (?,?,?)', (t, user_id, now()))
    c.commit(); c.close()
    return ok(mensagem='Conta criada com sucesso.', token=t, usuario=user_json(u)), 201


@app.post('/api/login')
def login():
    d = request.get_json(silent=True) or {}
    nome, senha = str(d.get('nome', '')).strip(), str(d.get('senha', ''))
    c = db(); u = c.execute('SELECT * FROM usuarios WHERE nome=? COLLATE NOCASE', (nome,)).fetchone()
    if not u or not check_password_hash(u['senha_hash'], senha):
        c.close(); return bad('Nome ou senha incorretos.', 401)
    t = secrets.token_urlsafe(64)
    c.execute('INSERT INTO sessoes VALUES (?,?,?)', (t, u['id'], now())); c.commit(); c.close()
    return ok(token=t, usuario=user_json(u))


@app.get('/api/me')
@login_required
def me(u):
    c = db()
    groups = c.execute('''SELECT grupos.id, grupos.nome FROM grupos JOIN usuario_grupos
                          ON usuario_grupos.grupo_id=grupos.id WHERE usuario_grupos.usuario_id=?
                          ORDER BY grupos.nome''', (u['id'],)).fetchall()
    series = c.execute('''SELECT series.id, series.nome, series.grupo_id, grupos.nome grupo_nome
                          FROM series JOIN usuario_series ON usuario_series.serie_id=series.id
                          JOIN grupos ON grupos.id=series.grupo_id
                          WHERE usuario_series.usuario_id=? ORDER BY grupos.nome, series.nome''', (u['id'],)).fetchall()
    c.close()
    return ok(usuario=user_json(u), grupos=[dict(x) for x in groups], series=[dict(x) for x in series])


@app.put('/api/me')
@login_required
def update_me(u):
    multipart = (
        request.content_type
        and request.content_type.startswith('multipart/form-data')
    )

    d = request.form if multipart else (request.get_json(silent=True) or {})

    nome = str(d.get('nome', u['nome'])).strip()
    senha = str(d.get('senha', ''))
    idioma = str(d.get('idioma', u['idioma'] if 'idioma' in u.keys() else 'en')).strip().lower()

    idiomas_validos = {'pt', 'en', 'es'}

    if not 2 <= len(nome) <= 30:
        return bad('O nome precisa ter entre 2 e 30 caracteres.')

    if idioma not in idiomas_validos:
        return bad('Idioma inválido. Use pt, en ou es.')

    if senha and not 6 <= len(senha) <= 200:
        return bad('A senha precisa ter entre 6 e 200 caracteres.')

    remover_imagem = str(d.get('remover_imagem', '')).lower() in {
        '1', 'true', 'sim', 'yes'
    }

    nova_imagem = request.files.get('imagem') if multipart else None

    c = db()

    try:
        if nome != u['nome']:
            existe = c.execute(
                'SELECT 1 FROM usuarios WHERE nome=? COLLATE NOCASE AND id<>?',
                (nome, u['id'])
            ).fetchone()

            if existe:
                c.close()
                return bad('Esse nome de usuário já está em uso.', 409)

        imagem_atual = u['imagem']
        imagem_final = imagem_atual

        if remover_imagem:
            imagem_final = None

        if nova_imagem and nova_imagem.filename:
            imagem_final, problem = save_image(nova_imagem, u['id'])

            if problem:
                c.close()
                return bad(problem)

        campos = [
            'nome=?',
            'imagem=?',
            'idioma=?'
        ]

        valores = [
            nome,
            imagem_final,
            idioma
        ]

        if senha:
            campos.append('senha_hash=?')
            valores.append(hash_password(senha))

        valores.append(u['id'])

        c.execute(
            'UPDATE usuarios SET ' + ', '.join(campos) + ' WHERE id=?',
            valores
        )

        c.commit()

        atualizado = c.execute(
            'SELECT * FROM usuarios WHERE id=?',
            (u['id'],)
        ).fetchone()

        c.close()

        # Remove a imagem antiga somente depois que a atualização deu certo.
        if (
            imagem_atual
            and imagem_atual != imagem_final
            and os.path.exists(os.path.join(UPLOADS, imagem_atual))
        ):
            try:
                os.remove(os.path.join(UPLOADS, imagem_atual))
            except OSError:
                pass

        return ok(
            mensagem='Perfil atualizado com sucesso.',
            usuario=user_json(atualizado)
        )

    except sqlite3.IntegrityError:
        c.rollback()
        c.close()
        return bad('Esse nome de usuário já está em uso.', 409)

    except Exception:
        c.rollback()
        c.close()
        return bad('Não foi possível atualizar o perfil.', 500)


@app.post('/api/logout')
@login_required
def logout(u):
    c = db(); c.execute('DELETE FROM sessoes WHERE token=?', (token(),)); c.commit(); c.close()
    return ok(mensagem='Sessão encerrada.')


@app.post('/api/grupos')
@login_required
def create_group(u):
    d = request.get_json(silent=True) or {}
    nome, senha = str(d.get('nome', '')).strip(), str(d.get('senha', ''))
    if not 2 <= len(nome) <= 80: return bad('Nome de grupo inválido.')
    if len(senha) < 4: return bad('A senha do grupo precisa ter pelo menos 4 caracteres.')
    gid = uid(); c = db()
    try:
        c.execute('INSERT INTO grupos VALUES (?,?,?,?,?)', (gid, nome, hash_password(senha), u['id'], now()))
        c.execute('INSERT INTO usuario_grupos VALUES (?,?,?)', (u['id'], gid, now()))
        c.commit()
    except sqlite3.IntegrityError:
        c.rollback(); c.close(); return bad('Esse grupo já existe.', 409)
    c.close(); return ok(grupo={'id': gid, 'nome': nome}), 201


@app.get('/api/grupos')
@login_required
def groups(u):
    c = db(); rows = c.execute('''SELECT g.id,g.nome,COUNT(ug.usuario_id) membros FROM grupos g
                                  LEFT JOIN usuario_grupos ug ON ug.grupo_id=g.id GROUP BY g.id ORDER BY g.nome''').fetchall(); c.close()
    return ok(grupos=[dict(x) for x in rows])


@app.post('/api/grupos/<gid>/entrar')
@login_required
def join_group(u, gid):
    d = request.get_json(silent=True) or {}; senha = str(d.get('senha', ''))
    c = db(); g = c.execute('SELECT * FROM grupos WHERE id=?', (gid,)).fetchone()
    if not g: c.close(); return bad('Grupo não encontrado.', 404)
    if not check_password_hash(g['senha_hash'], senha): c.close(); return bad('Senha do grupo incorreta.', 403)
    c.execute('INSERT OR IGNORE INTO usuario_grupos VALUES (?,?,?)', (u['id'], gid, now())); c.commit(); c.close()
    return ok(grupo={'id': gid, 'nome': g['nome']})


@app.post('/api/grupos/<gid>/series')
@login_required
def create_series(u, gid):
    d = request.get_json(silent=True) or {}; nome = str(d.get('nome', '')).strip(); senha = str(d.get('senha', ''))
    if not nome or len(nome) > 50: return bad('Nome de série inválido.')
    if len(senha) < 4: return bad('A senha da série precisa ter pelo menos 4 caracteres.')
    c = db()
    if not member(c, u['id'], 'usuario_grupos', 'grupo_id', gid): c.close(); return bad('Você não está no grupo.', 403)
    sid = uid()
    try:
        c.execute('INSERT INTO series VALUES (?,?,?,?,?,?)', (sid, gid, nome, hash_password(senha), u['id'], now()))
        c.execute('INSERT INTO usuario_series VALUES (?,?,?)', (u['id'], sid, now())); c.commit()
    except sqlite3.IntegrityError:
        c.rollback(); c.close(); return bad('Essa série já existe nesse grupo.', 409)
    c.close(); return ok(serie={'id': sid, 'nome': nome, 'grupo_id': gid}), 201


@app.get('/api/grupos/<gid>/series')
@login_required
def list_series(u, gid):
    c = db(); rows = c.execute('SELECT id,nome,grupo_id FROM series WHERE grupo_id=? ORDER BY nome', (gid,)).fetchall(); c.close()
    return ok(series=[dict(x) for x in rows])


@app.post('/api/series/<sid>/entrar')
@login_required
def join_series(u, sid):
    d = request.get_json(silent=True) or {}; senha = str(d.get('senha', ''))
    c = db(); s = c.execute('SELECT * FROM series WHERE id=?', (sid,)).fetchone()
    if not s: c.close(); return bad('Série não encontrada.', 404)
    if not member(c, u['id'], 'usuario_grupos', 'grupo_id', s['grupo_id']): c.close(); return bad('Entre no grupo primeiro.', 403)
    if not check_password_hash(s['senha_hash'], senha): c.close(); return bad('Senha da série incorreta.', 403)
    c.execute('INSERT OR IGNORE INTO usuario_series VALUES (?,?,?)', (u['id'], sid, now())); c.commit(); c.close()
    return ok(mensagem='Você entrou na série.')


@app.post('/api/series/<sid>/livros')
@login_required
def create_book(u, sid):
    d = request.get_json(silent=True) or {}; nome = str(d.get('nome', '')).strip(); numero = d.get('numero')
    if not nome: return bad('Digite o nome do livro.')
    try: numero = int(numero) if numero is not None else None
    except (TypeError, ValueError): return bad('Número de livro inválido.')
    c = db()
    if not member(c, u['id'], 'usuario_series', 'serie_id', sid): c.close(); return bad('Você não está na série.', 403)
    lid = uid()
    try:
        c.execute('INSERT INTO livros VALUES (?,?,?,?,?,?)', (lid, sid, nome, numero, u['id'], now())); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return bad('Esse livro já existe nessa série.', 409)
    c.close(); return ok(livro={'id': lid, 'nome': nome, 'numero': numero, 'serie_id': sid}), 201


@app.get('/api/series/<sid>/livros')
@login_required
def list_books(u, sid):
    c = db(); rows = c.execute('''SELECT id,nome,numero,serie_id FROM livros WHERE serie_id=?
                                  ORDER BY CASE WHEN numero IS NULL THEN 999999 ELSE numero END,nome''', (sid,)).fetchall(); c.close()
    return ok(livros=[dict(x) for x in rows])


@app.post('/api/livros/<lid>/materias')
@login_required
def create_subject(u, lid):
    d = request.get_json(silent=True) or {}; nome = str(d.get('nome', '')).strip()
    if not nome: return bad('Digite o nome da matéria.')
    c = db(); book = c.execute('SELECT * FROM livros WHERE id=?', (lid,)).fetchone()
    if not book: c.close(); return bad('Livro não encontrado.', 404)
    if not member(c, u['id'], 'usuario_series', 'serie_id', book['serie_id']): c.close(); return bad('Você não está na série.', 403)
    mid = uid()
    try:
        c.execute('INSERT INTO materias VALUES (?,?,?,?,?)', (mid, lid, nome, u['id'], now())); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return bad('Essa matéria já existe nesse livro.', 409)
    c.close(); return ok(materia={'id': mid, 'nome': nome, 'livro_id': lid}), 201


@app.get('/api/livros/<lid>/materias')
@login_required
def list_subjects(u, lid):
    c = db(); rows = c.execute('SELECT id,nome,livro_id FROM materias WHERE livro_id=? ORDER BY nome', (lid,)).fetchall(); c.close()
    return ok(materias=[dict(x) for x in rows])


@app.post('/api/materias/<mid>/capitulos')
@login_required
def create_chapter(u, mid):
    d = request.get_json(silent=True) or {}; numero = d.get('numero'); nome = str(d.get('nome', '')).strip() or None
    try: numero = int(numero)
    except (TypeError, ValueError): return bad('Número do capítulo é obrigatório.')
    if numero < 1: return bad('O capítulo precisa ser maior que zero.')
    c = db(); m = c.execute('''SELECT materias.*,livros.serie_id FROM materias JOIN livros ON livros.id=materias.livro_id WHERE materias.id=?''', (mid,)).fetchone()
    if not m: c.close(); return bad('Matéria não encontrada.', 404)
    if not member(c, u['id'], 'usuario_series', 'serie_id', m['serie_id']): c.close(); return bad('Você não está na série.', 403)
    cid = uid()
    try:
        c.execute('INSERT INTO capitulos VALUES (?,?,?,?,?,?)', (cid, mid, numero, nome, u['id'], now())); c.commit()
    except sqlite3.IntegrityError:
        c.close(); return bad('Esse capítulo já existe nessa matéria.', 409)
    c.close(); return ok(capitulo={'id': cid, 'numero': numero, 'nome': nome, 'materia_id': mid}), 201


@app.get('/api/materias/<mid>/capitulos')
@login_required
def list_chapters(u, mid):
    c = db(); rows = c.execute('SELECT id,numero,nome,materia_id FROM capitulos WHERE materia_id=? ORDER BY numero', (mid,)).fetchall(); c.close()
    return ok(capitulos=[dict(x) for x in rows])


@app.post('/api/mensagens')
@login_required
def create_message(u):
    multipart = request.content_type and request.content_type.startswith('multipart/form-data')
    d = request.form if multipart else (request.get_json(silent=True) or {})
    image = request.files.get('imagem') if multipart else None
    file = request.files.get('arquivo') if multipart else None
    category = str(d.get('categoria', '')).strip().lower()
    gid, sid = str(d.get('grupo_id', '')).strip(), str(d.get('serie_id', '')).strip()
    lid, mid, cid = d.get('livro_id'), d.get('materia_id'), d.get('capitulo_id')
    text = str(d.get('texto', '')).strip()
    if not gid or not sid: return bad('Grupo e série são obrigatórios.')
    if not text and not image and not file: return bad('A mensagem precisa ter texto, imagem ou arquivo.')
    c = db(); valid, problem = validate_chat(c, u['id'], category, gid, sid, lid, mid, cid)
    if not valid: c.close(); return bad(problem, 403)
    mid_msg = uid(); image_name, problem = save_image(image, mid_msg)
    if problem: c.close(); return bad(problem)
    file_name, problem = save_file(file, mid_msg)
    if problem:
        c.close()
        if image_name and os.path.exists(os.path.join(UPLOADS, image_name)): os.remove(os.path.join(UPLOADS, image_name))
        return bad(problem)
    c.execute('''INSERT INTO mensagens VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
              (mid_msg,u['id'],category,gid,sid,lid,mid,cid,text or None,image_name,file_name,now()))
    c.commit(); c.close()
    return ok(mensagem={'id':mid_msg,'usuario_id':u['id'],'usuario_nome':u['nome'],'categoria':category,'grupo_id':gid,'serie_id':sid,'livro_id':lid,'materia_id':mid,'capitulo_id':cid,'texto':text,'imagem':image_name,'arquivo':file_name}), 201


@app.get('/api/mensagens')
@login_required
def list_messages(u):
    category = request.args.get('categoria'); gid = request.args.get('grupo_id'); sid = request.args.get('serie_id')
    lid, mid, cid = request.args.get('livro_id'), request.args.get('materia_id'), request.args.get('capitulo_id')
    try: limit = max(1, min(int(request.args.get('limite', 100)), 200))
    except ValueError: limit = 100
    if not gid or not sid: return bad('grupo_id e serie_id são obrigatórios.')
    c = db()
    if not member(c, u['id'], 'usuario_series', 'serie_id', sid): c.close(); return bad('Você não está nessa série.', 403)
    q = '''SELECT mensagens.*,usuarios.nome usuario_nome,usuarios.imagem usuario_imagem
           FROM mensagens JOIN usuarios ON usuarios.id=mensagens.usuario_id
           WHERE mensagens.grupo_id=? AND mensagens.serie_id=?'''
    p = [gid, sid]
    if category:
        if category not in CATEGORIES: c.close(); return bad('Categoria inválida.')
        q += ' AND mensagens.categoria=?'; p.append(category)
    for col, val in [('livro_id',lid),('materia_id',mid),('capitulo_id',cid)]:
        if val: q += f' AND mensagens.{col}=?'; p.append(val)
    q += ' ORDER BY mensagens.criado_em DESC LIMIT ?'; p.append(limit)
    rows = c.execute(q, p).fetchall(); c.close()
    rows = list(reversed(rows))
    return ok(mensagens=[dict(x) for x in rows])


@app.post('/api/capitulos/<cid>/resumos')
@login_required
def create_summary(u, cid):
    title = request.form.get('titulo', '').strip(); text = request.form.get('texto', '').strip()
    image, file = request.files.get('imagem'), request.files.get('arquivo')
    if not text and not image and not file: return bad('O resumo precisa ter texto, imagem ou arquivo.')
    c = db(); chapter = c.execute('''SELECT capitulos.id,livros.serie_id FROM capitulos
                                     JOIN materias ON materias.id=capitulos.materia_id
                                     JOIN livros ON livros.id=materias.livro_id WHERE capitulos.id=?''', (cid,)).fetchone()
    if not chapter: c.close(); return bad('Capítulo não encontrado.', 404)
    if not member(c, u['id'], 'usuario_series', 'serie_id', chapter['serie_id']): c.close(); return bad('Você não está nessa série.', 403)
    rid = uid(); image_name, problem = save_image(image, rid)
    if problem: c.close(); return bad(problem)
    file_name, problem = save_file(file, rid)
    if problem:
        c.close()
        if image_name and os.path.exists(os.path.join(UPLOADS, image_name)): os.remove(os.path.join(UPLOADS, image_name))
        return bad(problem)
    t = now(); c.execute('INSERT INTO resumos VALUES (?,?,?,?,?,?,?,?,?)', (rid,cid,u['id'],title or None,text,file_name,image_name,t,t)); c.commit(); c.close()
    return ok(resumo={'id':rid,'capitulo_id':cid,'usuario_id':u['id'],'usuario_nome':u['nome'],'titulo':title,'texto':text,'arquivo':file_name,'imagem':image_name,'criado_em':t,'atualizado_em':t}), 201


@app.get('/api/capitulos/<cid>/resumos')
@login_required
def list_summaries(u, cid):
    c = db(); chapter = c.execute('''SELECT capitulos.id,livros.serie_id FROM capitulos JOIN materias ON materias.id=capitulos.materia_id JOIN livros ON livros.id=materias.livro_id WHERE capitulos.id=?''', (cid,)).fetchone()
    if not chapter: c.close(); return bad('Capítulo não encontrado.', 404)
    if not member(c, u['id'], 'usuario_series', 'serie_id', chapter['serie_id']): c.close(); return bad('Você não está nessa série.', 403)
    rows = c.execute('''SELECT resumos.*,usuarios.nome usuario_nome,usuarios.imagem usuario_imagem
                        FROM resumos JOIN usuarios ON usuarios.id=resumos.usuario_id
                        WHERE resumos.capitulo_id=? ORDER BY resumos.criado_em DESC''', (cid,)).fetchall(); c.close()
    return ok(resumos=[dict(x) for x in rows])


@app.get('/uploads/<path:name>')
def uploads(name):
    return send_from_directory(UPLOADS, os.path.basename(name))


@app.errorhandler(413)
def too_large(e):
    return bad('O arquivo enviado é grande demais.', 413)


@app.errorhandler(404)
def not_found(e):
    return bad('Rota não encontrada.', 404)


if __name__ == '__main__':
    print('=' * 60)
    print('CHAT ESCOLA API v2.0')
    print('=' * 60)
    print('Servidor: http://127.0.0.1:5000')
    print('Banco:    ' + DB)
    print('Uploads:  ' + UPLOADS)
    print('')
    print('POST /api/register')
    print('POST /api/login')
    print('GET  /api/me')
    print('PUT  /api/me')
    print('POST /api/logout')
    print('POST /api/grupos')
    print('POST /api/grupos/<id>/entrar')
    print('POST /api/grupos/<id>/series')
    print('POST /api/series/<id>/entrar')
    print('POST /api/series/<id>/livros')
    print('POST /api/livros/<id>/materias')
    print('POST /api/materias/<id>/capitulos')
    print('POST /api/mensagens')
    print('GET  /api/mensagens')
    print('POST /api/capitulos/<id>/resumos')
    print('GET  /api/capitulos/<id>/resumos')
    print('=' * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)

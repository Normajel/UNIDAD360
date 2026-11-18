"""Control de Entrega de Unidades - API local independiente.
Iniciar: uvicorn app:app --reload --host 127.0.0.1 --port 8000
"""
import io, os, re, json, sqlite3, secrets, hashlib, hmac, time, uuid, zipfile, tempfile, csv
import qrcode
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from PIL import Image, ImageOps
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image as PDFImage
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from xml.sax.saxutils import escape

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('UNIDADES_DATA_DIR', str(ROOT/'data')))
UPLOAD=DATA/'photos'; QR_DIR=DATA/'qr'
DATA.mkdir(parents=True,exist_ok=True); UPLOAD.mkdir(exist_ok=True); QR_DIR.mkdir(exist_ok=True)
DB=DATA/'units.sqlite3'
SESSION_SECONDS=8*3600
SESSIONS={}
LOGIN_FAILURES={}  # Límite simple por origen para uso local; se reinicia con el servidor
app=FastAPI(title='Control de Entrega de Unidades', version='2.0.0')
app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')

CHECKS=['Revisión con plano producción','Poliuretano','Pintura','Guardapolvos','Ventanas y seguros','Aseo y entrega','Cerraduras','Puertas','Piso','Prueba hidráulica (fotos, registros)','WC','Lavamanos','Duchas','Sello Contemar en artefactos','Lavaplatos','Prueba eléctrica: certificado','Revisión de tablero','Luminaria general','Enchufes','Interruptores','Puesta a tierra','Aire acondicionado','Colocación sello en puertas de acceso']
CODES=['C4OFBA','C4BOD','C4BODHC','C4BB','C2OFPL','C2OFBA','C2OFCOM','C2OFSV','C2OFESP','C2BOD','C2VEST','C2VESP','C1OFPL','C1OFESP','M2OFPL','M2OFBA','M2OFCOM','M2OFSV','M2OFESP','M2BB','M2BOD','M2VEST','M2VESP','M1BOD','M1ESP']

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def password_digest(password,salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),390000).hex()

@contextmanager
def db():
    conn=sqlite3.connect(DB,timeout=15)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:conn.close()

def init_db():
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS types(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, category TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS template_items(id INTEGER PRIMARY KEY, type_id INTEGER NOT NULL REFERENCES types(id), title TEXT NOT NULL, applies INTEGER NOT NULL DEFAULT 1, position INTEGER NOT NULL, UNIQUE(type_id,title));
        CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('trabajador','supervisor')), qr_value TEXT UNIQUE, qr_filename TEXT, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS units(id INTEGER PRIMARY KEY, code TEXT NOT NULL, detail TEXT NOT NULL CHECK(detail IN ('arriendo','stock','nv')), type_id INTEGER NOT NULL REFERENCES types(id), nv TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, completed_at TEXT, received_at TEXT, deliverer_id INTEGER REFERENCES people(id), receiver_id INTEGER REFERENCES people(id), observations TEXT NOT NULL DEFAULT '', UNIQUE(code,type_id,detail));
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE, title TEXT NOT NULL, position INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pendiente' CHECK(state IN ('pendiente','vb','na')), UNIQUE(unit_id,title));
        CREATE TABLE IF NOT EXISTS photos(id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE, filename TEXT NOT NULL UNIQUE, caption TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, unit_id INTEGER REFERENCES units(id), actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        ''')
        cols={r['name'] for r in c.execute('PRAGMA table_info(people)')}
        if 'rut' not in cols:c.execute("ALTER TABLE people ADD COLUMN rut TEXT")
        if 'position' not in cols:c.execute("ALTER TABLE people ADD COLUMN position TEXT NOT NULL DEFAULT ''")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_people_rut_unique ON people(rut) WHERE rut IS NOT NULL AND rut != ''")
        if not c.execute('SELECT 1 FROM types LIMIT 1').fetchone():
            for code in CODES:
                c.execute('INSERT INTO types(code,category) VALUES (?,?)',(code,'Catálogo inicial'))
                type_id=c.execute('SELECT last_insert_rowid()').fetchone()[0]
                for i,label in enumerate(CHECKS):c.execute('INSERT INTO template_items(type_id,title,position) VALUES (?,?,?)',(type_id,label,i))
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            password=os.environ.get('UNIDADES_ADMIN_PASSWORD')
            if not password:
                raise RuntimeError('Configura UNIDADES_ADMIN_PASSWORD antes de iniciar. Mínimo 12 caracteres.')
            if len(password)<12:raise RuntimeError('UNIDADES_ADMIN_PASSWORD debe tener al menos 12 caracteres')
            salt=secrets.token_hex(16); digest=password_digest(password,salt)
            c.execute('INSERT INTO users(username,password_hash,salt,role) VALUES (?,?,?,?)',('admin',digest,salt,'admin'))

def asdict(row):return dict(row) if row else None

def user_of(request:Request):
    token=request.cookies.get('unidades_session','')
    data=SESSIONS.get(token)
    if not data or data['expires']<time.time():
        SESSIONS.pop(token,None);raise HTTPException(401,'Debes iniciar sesión')
    return data['username']

def require_csrf(request:Request):
    token=request.cookies.get('unidades_session','')
    data=SESSIONS.get(token)
    if not data or data['expires']<time.time():raise HTTPException(401,'Sesión no válida')
    if not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),data['csrf']):raise HTTPException(403,'Token CSRF incorrecto')
    return data['username']

def audit(c,unit_id,actor,action,detail=''):
    c.execute('INSERT INTO audit(unit_id,actor,action,detail,created_at) VALUES (?,?,?,?,?)',(unit_id,actor,action,detail,now()))

def load_unit(c,uid):
    row=c.execute('''SELECT u.*,t.code AS type_code,t.category AS category,p.name AS deliverer_name,p.position AS deliverer_position,p.rut AS deliverer_rut,p.qr_filename AS deliverer_qr,s.name AS receiver_name,s.position AS receiver_position,s.rut AS receiver_rut,s.qr_filename AS receiver_qr
       FROM units u JOIN types t ON t.id=u.type_id LEFT JOIN people p ON p.id=u.deliverer_id LEFT JOIN people s ON s.id=u.receiver_id WHERE u.id=?''',(uid,)).fetchone()
    if not row:raise HTTPException(404,'Unidad inexistente')
    d=dict(row)
    d['reviews']=[dict(x) for x in c.execute('SELECT * FROM reviews WHERE unit_id=? ORDER BY position',(uid,))]
    d['photos']=[dict(x) for x in c.execute('SELECT * FROM photos WHERE unit_id=? ORDER BY id',(uid,))]
    d['audit']=[dict(x) for x in c.execute('SELECT * FROM audit WHERE unit_id=? ORDER BY id DESC LIMIT 60',(uid,))]
    n=len(d['reviews']); vb=sum(x['state']=='vb' for x in d['reviews']); na=sum(x['state']=='na' for x in d['reviews']); pending=n-vb-na
    applicable=n-na
    d.update(total=n,vb=vb,na=na,pending=pending,progress=round(vb/applicable*100) if applicable else 0)
    # Una revisión terminada no equivale a recepción: recepción final exige ambas identidades y controles aplicables con V°B°.
    d['status']='finalizada' if d['received_at'] else 'pendiente' if d['started_at'] else 'no_iniciada'
    d['ready_to_receive']=bool(d['started_at'] and pending==0 and applicable>0 and d['deliverer_id'] and d['receiver_id'] and not d['received_at'])
    return d

class Login(BaseModel):username:str;password:str
class UnitNew(BaseModel):code:str=Field(min_length=1,max_length=100);detail:str;type_id:int;nv:Optional[str]='';observations:str=''
class UnitPatch(BaseModel):nv:Optional[str]=None;observations:Optional[str]=None
class ReviewPatch(BaseModel):state:str
class PersonNew(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    role:str
    rut:str=Field(min_length=8,max_length=16)
    position:str=Field(min_length=2,max_length=100)
class PersonEdit(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    role:str
    rut:str=Field(min_length=8,max_length=16)
    position:str=Field(min_length=2,max_length=100)
class QrLookup(BaseModel):value:str=Field(min_length=8,max_length=300)
class TypeNew(BaseModel):code:str=Field(min_length=2,max_length=80);category:str=''
class TemplatePatch(BaseModel):items:list[dict]
class TemplateCopy(BaseModel):source_type_id:int
class AttachPerson(BaseModel):person_id:int
class PhotoCaption(BaseModel):caption:str=''

@app.on_event('startup')
def startup():init_db()

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')
@app.post('/api/login')
def login(payload:Login,request:Request):
    # Bloqueo temporal ante repetidos intentos fallidos, por dirección local de origen.
    origin=payload.username.lower().strip()+'@'+('local' if not request.client else request.client.host)
    attempts=[t for t in LOGIN_FAILURES.get(origin,[]) if time.time()-t<900]
    LOGIN_FAILURES[origin]=attempts
    if len(attempts)>=5:raise HTTPException(429,'Demasiados intentos. Reintenta en 15 minutos.')
    with db() as c:u=c.execute('SELECT * FROM users WHERE username=?',(payload.username,)).fetchone()
    valid=bool(u and hmac.compare_digest(password_digest(payload.password,u['salt']),u['password_hash']))
    if not valid:
        LOGIN_FAILURES[origin].append(time.time())
        raise HTTPException(401,'Credenciales incorrectas')
    LOGIN_FAILURES.pop(origin,None)
    token=secrets.token_urlsafe(40);csrf=secrets.token_urlsafe(32)
    SESSIONS[token]={'username':u['username'],'csrf':csrf,'expires':time.time()+SESSION_SECONDS}
    response=Response(content=json.dumps({'username':u['username'],'csrf':csrf}),media_type='application/json')
    response.set_cookie('unidades_session',token,httponly=True,samesite='strict',secure=os.environ.get('UNIDADES_HTTPS')=='1',max_age=SESSION_SECONDS)
    return response
@app.get('/api/me')
def me(request:Request):
    username=user_of(request); token=request.cookies['unidades_session']
    return {'username':username,'csrf':SESSIONS[token]['csrf']}
@app.post('/api/logout')
def logout(request:Request):
    require_csrf(request); SESSIONS.pop(request.cookies.get('unidades_session'),None)
    r=Response(status_code=204);r.delete_cookie('unidades_session');return r
class PasswordChange(BaseModel):
    current_password:str
    new_password:str

@app.post('/api/admin/change-password')
def change_password(payload:PasswordChange,request:Request):
    actor=require_csrf(request)
    if len(payload.new_password)<12 or len(payload.new_password)>256:
        raise HTTPException(400,'La nueva contraseña debe tener entre 12 y 256 caracteres')
    if payload.new_password==payload.current_password:
        raise HTTPException(400,'La contraseña nueva debe ser diferente')
    with db() as c:
        u=c.execute('SELECT * FROM users WHERE username=?',(actor,)).fetchone()
        if not u or not hmac.compare_digest(password_digest(payload.current_password,u['salt']),u['password_hash']):
            raise HTTPException(403,'Contraseña actual incorrecta')
        salt=secrets.token_hex(16)
        c.execute('UPDATE users SET salt=?,password_hash=? WHERE id=?',(salt,password_digest(payload.new_password,salt),u['id']))
        audit(c,None,actor,'seguridad','Cambio de contraseña de administrador')
    # Mantiene solamente la sesión que ejecutó el cambio.
    current=request.cookies.get('unidades_session')
    for token in list(SESSIONS):
        if token!=current:SESSIONS.pop(token,None)
    return {'ok':True,'message':'Contraseña actualizada; otras sesiones cerradas'}

@app.get('/api/admin/audit')
def audit_general(request:Request,limit:int=150):
    user_of(request)
    limit=max(1,min(limit,300))
    with db() as c:
        return [dict(r) for r in c.execute("""SELECT a.id,a.unit_id,u.code AS unit_code,a.actor,a.action,a.detail,a.created_at
             FROM audit a LEFT JOIN units u ON u.id=a.unit_id ORDER BY a.id DESC LIMIT ?""",(limit,))]

@app.get('/api/admin/backup')
def download_backup(request:Request):
    actor=user_of(request)
    # Solo lectura: respalda la BD de forma consistente mediante SQLite backup, aun con WAL activo.
    with db() as c:audit(c,None,actor,'respaldo','Descarga de copia de seguridad solicitada')
    buf=io.BytesIO()
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    manifest={'format':'unidad360-backup-v1','created_at':now(),'files':{}}
    with tempfile.TemporaryDirectory() as temp:
        snapshot=Path(temp)/'units.sqlite3'
        source=sqlite3.connect(DB)
        target=sqlite3.connect(snapshot)
        try:source.backup(target)
        finally:target.close();source.close()
        items=[('units.sqlite3',snapshot)]
        for folder in ('photos','qr'):
            base=DATA/folder
            if base.exists():
                for path in sorted(base.iterdir()):
                    if path.is_file() and not path.is_symlink():items.append((folder+'/'+path.name,path))
        with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,path in items:
                raw=path.read_bytes()
                manifest['files'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}
                z.writestr(name,raw)
            z.writestr('manifest.json',json.dumps(manifest,indent=2,ensure_ascii=False))
    buf.seek(0)
    return StreamingResponse(buf,media_type='application/zip',headers={
        'Content-Disposition':f'attachment; filename="UNIDAD360_respaldo_{stamp}.zip"',
        'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

@app.get('/api/types')
def types(request:Request):
    user_of(request)
    with db() as c:return [dict(x) for x in c.execute('SELECT * FROM types WHERE active=1 ORDER BY code')]
@app.post('/api/types')
def create_type(payload:TypeNew,request:Request):
    require_csrf(request)
    with db() as c:
        try:
            c.execute('INSERT INTO types(code,category) VALUES (?,?)',(payload.code.strip().upper(),payload.category.strip()))
        except sqlite3.IntegrityError:raise HTTPException(409,'Este tipo ya existe')
        tid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
        for i,label in enumerate(CHECKS):c.execute('INSERT INTO template_items(type_id,title,position) VALUES (?,?,?)',(tid,label,i))
    return {'id':tid}
@app.get('/api/types/{type_id}/template')
def template(type_id:int,request:Request):
    user_of(request)
    with db() as c:return [dict(x) for x in c.execute('SELECT * FROM template_items WHERE type_id=? ORDER BY position',(type_id,))]
@app.put('/api/types/{type_id}/template')
def template_save(type_id:int,payload:TemplatePatch,request:Request):
    require_csrf(request)
    if len(payload.items)>100:raise HTTPException(400,'Máximo 100 controles')
    if not payload.items:raise HTTPException(400,'La plantilla necesita al menos un control')
    if not any(item.get('applies',True) for item in payload.items):raise HTTPException(400,'Debe existir al menos un control aplicable')
    titles=[]
    for item in payload.items:
        title=str(item.get('title','')).strip()
        if not title or len(title)>180:raise HTTPException(400,'Nombre de control inválido')
        titles.append(title)
    if len(set(titles))!=len(titles):raise HTTPException(400,'Controles duplicados')
    with db() as c:
        if not c.execute('SELECT 1 FROM types WHERE id=?',(type_id,)).fetchone():raise HTTPException(404,'Tipo inexistente')
        c.execute('DELETE FROM template_items WHERE type_id=?',(type_id,))
        for i,item in enumerate(payload.items):c.execute('INSERT INTO template_items(type_id,title,applies,position) VALUES (?,?,?,?)',(type_id,titles[i],int(bool(item.get('applies',True))),i))
    return {'ok':True,'note':'La plantilla aplica solo a futuros registros; no altera informes existentes.'}

@app.post('/api/types/{type_id}/template/copy')
def template_copy(type_id:int,payload:TemplateCopy,request:Request):
    require_csrf(request)
    if type_id==payload.source_type_id:raise HTTPException(400,'Selecciona un tipo distinto para copiar')
    with db() as c:
        dst=c.execute('SELECT 1 FROM types WHERE id=? AND active=1',(type_id,)).fetchone()
        src=c.execute('SELECT 1 FROM types WHERE id=? AND active=1',(payload.source_type_id,)).fetchone()
        if not dst or not src:raise HTTPException(404,'Tipo de unidad inexistente')
        rows=c.execute('SELECT title,applies,position FROM template_items WHERE type_id=? ORDER BY position',(payload.source_type_id,)).fetchall()
        if not rows:raise HTTPException(400,'La plantilla de origen no tiene controles')
        c.execute('DELETE FROM template_items WHERE type_id=?',(type_id,))
        for i,row in enumerate(rows):
            c.execute('INSERT INTO template_items(type_id,title,applies,position) VALUES (?,?,?,?)',(type_id,row['title'],row['applies'],i))
    return {'ok':True,'copied':len(rows),'note':'Plantilla copiada. Solo afecta a unidades que registres desde ahora.'}

@app.get('/api/people')
def people(request:Request):
    user_of(request)
    with db() as c:return [dict(x) for x in c.execute('SELECT * FROM people ORDER BY active DESC,role,name')]
def valid_rut(rut:str):
    raw=re.sub(r'[.\-\s]','',rut).upper()
    if not re.fullmatch(r'\d{7,8}[0-9K]',raw):raise HTTPException(400,'RUT inválido: revisa formato')
    seq=2;total=0
    for digit in reversed(raw[:-1]):
        total+=int(digit)*seq;seq=2 if seq==7 else seq+1
    check=11-total%11
    expected='0' if check==11 else 'K' if check==10 else str(check)
    if raw[-1]!=expected:raise HTTPException(400,'Dígito verificador de RUT incorrecto')
    return raw[:-1]+'-'+raw[-1]

def make_person_qr(c,pid):
    value='RESP-'+secrets.token_hex(16).upper()
    # Token aleatorio no adivinable, sin RUT ni información personal.
    filename=f'resp-{pid}.png'
    im=qrcode.make(value,box_size=10,border=3)
    im.save(QR_DIR/filename)
    c.execute('UPDATE people SET qr_value=?,qr_filename=? WHERE id=?',(value,filename,pid))
    return value

@app.post('/api/people')
def person_create(payload:PersonNew,request:Request):
    require_csrf(request)
    if payload.role not in ('trabajador','supervisor'):raise HTTPException(400,'Rol incorrecto')
    rut=valid_rut(payload.rut)
    with db() as c:
        try:
            c.execute('INSERT INTO people(name,role,rut,position) VALUES (?,?,?,?)',(payload.name.strip(),payload.role,rut,payload.position.strip()))
            pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
            make_person_qr(c,pid)
        except sqlite3.IntegrityError:raise HTTPException(409,'RUT ya registrado')
    return {'id':pid,'message':'Responsable y QR creados automáticamente'}

@app.put('/api/people/{pid}')
def edit_person(pid:int,payload:PersonEdit,request:Request):
    require_csrf(request)
    if payload.role not in ('trabajador','supervisor'):raise HTTPException(400,'Rol incorrecto')
    rut=valid_rut(payload.rut)
    with db() as c:
        row=c.execute('SELECT * FROM people WHERE id=?',(pid,)).fetchone()
        if not row:raise HTTPException(404,'Responsable inexistente')
        # No alterar el rol de una persona ya registrada en entregas o recepciones.
        used=c.execute('SELECT 1 FROM units WHERE deliverer_id=? OR receiver_id=? LIMIT 1',(pid,pid)).fetchone()
        if used and payload.role!=row['role']:raise HTTPException(409,'El rol de este responsable ya usado no se puede cambiar')
        try:c.execute('UPDATE people SET name=?,role=?,rut=?,position=? WHERE id=?',(payload.name.strip(),payload.role,rut,payload.position.strip(),pid))
        except sqlite3.IntegrityError:raise HTTPException(409,'RUT ya registrado')
    return {'ok':True}

@app.post('/api/people/{pid}/deactivate')
def deactivate_person(pid:int,request:Request):
    require_csrf(request)
    with db() as c:
        if not c.execute('SELECT 1 FROM people WHERE id=?',(pid,)).fetchone():raise HTTPException(404,'Responsable inexistente')
        c.execute('UPDATE people SET active=0 WHERE id=?',(pid,))
    return {'ok':True}

@app.post('/api/people/{pid}/activate')
def activate_person(pid:int,request:Request):
    require_csrf(request)
    with db() as c:
        row=c.execute('SELECT id,active FROM people WHERE id=?',(pid,)).fetchone()
        if not row:raise HTTPException(404,'Responsable inexistente')
        c.execute('UPDATE people SET active=1 WHERE id=?',(pid,))
    return {'ok':True}

@app.delete('/api/people/{pid}')
def delete_person(pid:int,request:Request):
    require_csrf(request)
    with db() as c:
        row=c.execute('SELECT * FROM people WHERE id=?',(pid,)).fetchone()
        if not row:raise HTTPException(404,'Responsable inexistente')
        used=c.execute('SELECT 1 FROM units WHERE deliverer_id=? OR receiver_id=? LIMIT 1',(pid,pid)).fetchone()
        if used:raise HTTPException(409,'Este responsable ya figura en una entrega o recepción. No puede eliminarse porque se perdería trazabilidad. Puedes desactivarlo y conservarlo en el historial.')
        c.execute('DELETE FROM people WHERE id=?',(pid,))
    # El archivo QR se elimina solo después de confirmar la eliminación en la base.
    if row['qr_filename']:
        path=QR_DIR/row['qr_filename']
        if path.name==row['qr_filename'] and path.is_file():path.unlink(missing_ok=True)
    return {'ok':True}

@app.post('/api/people/resolve-qr')
def resolve_qr(payload:QrLookup,request:Request):
    user_of(request)
    with db() as c:
        row=c.execute('SELECT id,name,role,position,rut,qr_value FROM people WHERE qr_value=? AND active=1',(payload.value.strip(),)).fetchone()
        if not row:raise HTTPException(404,'QR no registrado o responsable inactivo')
        return dict(row)

@app.get('/api/people/{pid}/credential')
def person_credential(pid:int,request:Request):
    user_of(request)
    with db() as c:row=c.execute('SELECT * FROM people WHERE id=?',(pid,)).fetchone()
    if not row:raise HTTPException(404,'Responsable inexistente')
    sty=getSampleStyleSheet();buf=io.BytesIO()
    doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=25*mm,rightMargin=25*mm)
    role='ENTREGA' if row['role']=='trabajador' else 'RECEPCIÓN'
    flow=[Paragraph('CREDENCIAL DE RESPONSABLE',sty['Heading1']),Spacer(1,15),Paragraph(escape(row['name']),sty['Heading2']),Paragraph('Cargo: '+escape(row['position'] or 'Sin cargo'),sty['Normal']),Paragraph('RUT: '+escape(row['rut'] or 'No registrado'),sty['Normal']),Paragraph('Rol: '+role,sty['Normal']),Spacer(1,15)]
    if row['qr_filename'] and (QR_DIR/row['qr_filename']).exists():flow.append(pdf_image(QR_DIR/row['qr_filename'],65*mm,65*mm))
    flow.extend([Spacer(1,8),Paragraph('Código interno: '+escape(row['qr_value'] or '—'),sty['Normal']),Spacer(1,10),Paragraph('El QR identifica un registro; no reemplaza autenticación ni firma.',sty['Normal'])])
    doc.build(flow);buf.seek(0)
    return StreamingResponse(buf,media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="credencial_{pid}.pdf"','Cache-Control':'no-store'})

@app.get('/api/people/{pid}/qr-image')
def get_qr(pid:int,request:Request):
    user_of(request)
    with db() as c:r=c.execute('SELECT qr_filename FROM people WHERE id=?',(pid,)).fetchone()
    if not r or not r['qr_filename'] or not (QR_DIR/r['qr_filename']).exists():raise HTTPException(404,'QR sin imagen')
    return FileResponse(QR_DIR/r['qr_filename'])
@app.get('/api/units')
def units(request:Request,q:str='',status:str='',type_id:Optional[int]=None,
          detail:str='',date_from:str='',date_to:str=''):
    user_of(request)
    if status and status not in ('finalizada','pendiente','no_iniciada'):
        raise HTTPException(400,'Estado inválido')
    if detail and detail not in ('stock','arriendo','nv'):
        raise HTTPException(400,'Detalle inválido')
    for value in (date_from,date_to):
        if value:
            try:
                if datetime.strptime(value,'%Y-%m-%d').strftime('%Y-%m-%d')!=value:
                    raise ValueError()
            except ValueError:
                raise HTTPException(400,'Fecha inválida: utiliza AAAA-MM-DD')
    if date_from and date_to and date_from>date_to:
        raise HTTPException(400,'El inicio del período no puede ser posterior al final')
    conditions=[]; params=[]
    if type_id is not None:
        conditions.append('type_id=?');params.append(type_id)
    if detail:
        conditions.append('detail=?');params.append(detail)
    if date_from:
        conditions.append('substr(created_at,1,10)>=?');params.append(date_from)
    if date_to:
        conditions.append('substr(created_at,1,10)<=?');params.append(date_to)
    # Si el filtro textual existe, se aplica también sobre el código del tipo.
    sql='SELECT id FROM units'
    if conditions:sql+=' WHERE '+' AND '.join(conditions)
    sql+=' ORDER BY id DESC'
    with db() as c:
        ids=[r['id'] for r in c.execute(sql,params)]
        data=[load_unit(c,i) for i in ids]
    if q:
        search=q.strip().casefold()
        data=[x for x in data if search in ' '.join([x['code'],x['type_code'],x['nv'] or '',x['detail']]).casefold()]
    if status:data=[x for x in data if x['status']==status]
    for x in data:x.pop('audit',None)
    return data

@app.get('/api/dashboard/summary')
def dashboard_summary(request:Request):
    user_of(request)
    with db() as c:
        rows=[load_unit(c,r['id']) for r in c.execute('SELECT id FROM units ORDER BY id DESC').fetchall()]
    counts={key:sum(d['status']==key for d in rows) for key in ('finalizada','pendiente','no_iniciada')}
    counts['total']=len(rows)
    counts['ready_for_reception']=sum(d['ready_to_receive'] for d in rows)
    counts['pending_checks']=sum(d['pending'] for d in rows if not d['received_at'])
    counts['completed_without_reception']=sum(d['pending']==0 and d['started_at'] and not d['received_at'] for d in rows)
    counts['percentage_finalized']=round(100*counts['finalizada']/len(rows)) if rows else 0
    return counts

def report_filters(date_from: str, date_to: str, type_id: Optional[int], detail: str):
    for val in (date_from, date_to):
        if val:
            try:
                if datetime.strptime(val, '%Y-%m-%d').strftime('%Y-%m-%d') != val:
                    raise ValueError()
            except ValueError:
                raise HTTPException(400, 'Fecha inválida: utiliza AAAA-MM-DD')
    if date_from and date_to and date_from > date_to:
        raise HTTPException(400, 'El inicio del período no puede ser posterior al final')
    if detail and detail not in ('stock', 'arriendo', 'nv'):
        raise HTTPException(400, 'Detalle inválido')
    clauses=[]; args=[]
    if date_from: clauses.append('substr(u.created_at,1,10)>=?'); args.append(date_from)
    if date_to: clauses.append('substr(u.created_at,1,10)<=?'); args.append(date_to)
    if type_id is not None: clauses.append('u.type_id=?'); args.append(type_id)
    if detail: clauses.append('u.detail=?'); args.append(detail)
    return (' WHERE ' + ' AND '.join(clauses) if clauses else ''), args

def report_data(date_from='', date_to='', type_id=None, detail=''):
    where, args=report_filters(date_from,date_to,type_id,detail)
    with db() as c:
        rows=c.execute("""SELECT u.id,u.code,u.detail,u.nv,u.created_at,u.started_at,u.received_at,
                        t.code type_code,t.id type_id, p.name deliverer_name,s.name receiver_name,
                        (SELECT COUNT(*) FROM reviews r WHERE r.unit_id=u.id AND r.state='pendiente') pending,
                        (SELECT COUNT(*) FROM reviews r WHERE r.unit_id=u.id AND r.state='vb') vb,
                        (SELECT COUNT(*) FROM reviews r WHERE r.unit_id=u.id AND r.state='na') na
                        FROM units u JOIN types t ON t.id=u.type_id
                        LEFT JOIN people p ON p.id=u.deliverer_id
                        LEFT JOIN people s ON s.id=u.receiver_id""" + where + ' ORDER BY u.created_at DESC,u.id DESC',args).fetchall()
    data=[]
    for r in rows:
        d=dict(r)
        d['status']='finalizada' if d['received_at'] else 'pendiente' if d['started_at'] else 'no_iniciada'
        applicable=d['vb']+d['pending']
        d['progress']=round(100*d['vb']/applicable) if applicable else 0
        data.append(d)
    status_counts={k:sum(d['status']==k for d in data) for k in ('finalizada','pendiente','no_iniciada')}
    detail_counts={k:sum(d['detail']==k for d in data) for k in ('stock','arriendo','nv')}
    models={}
    for r in data:
        k=r['type_code'];entry=models.setdefault(k,{'type_code':k,'total':0,'finalizada':0,'pendiente':0,'no_iniciada':0})
        entry['total']+=1; entry[r['status']]+=1
    months={}
    for r in data:
        k=r['created_at'][:7];entry=months.setdefault(k,{'month':k,'total':0,'received':0})
        entry['total']+=1;entry['received']+=bool(r['received_at'])
    total=len(data)
    return {'filters':{'date_from':date_from,'date_to':date_to,'type_id':type_id,'detail':detail},
            'totals':{'total':total, **status_counts,'percentage_finalized':round(status_counts['finalizada']*100/total) if total else 0,
                      'pending_checks':sum(r['pending'] for r in data if not r['received_at']),
                      'awaiting_reception':sum(bool(r['started_at'] and r['pending']==0 and not r['received_at']) for r in data)},
            'by_detail':detail_counts,'by_type':sorted(models.values(),key=lambda r:(-r['total'],r['type_code'])),
            'by_month':sorted(months.values(),key=lambda r:r['month']), 'units':data}

@app.get('/api/reports/summary')
def reports_summary(request:Request,date_from:str='',date_to:str='',type_id:Optional[int]=None,detail:str=''):
    user_of(request)
    return report_data(date_from,date_to,type_id,detail)

@app.get('/api/reports/export.csv')
def reports_csv(request:Request,date_from:str='',date_to:str='',type_id:Optional[int]=None,detail:str=''):
    user_of(request)
    data=report_data(date_from,date_to,type_id,detail)
    output=io.StringIO(newline='')
    output.write('\ufeff')  # Excel UTF-8 BOM
    writer=csv.writer(output)
    writer.writerow(['Código unidad','Tipo','Detalle','Nota de venta','Fecha creación UTC','Fecha recepción UTC','Estado','V°B°','N/A','Pendientes','Porcentaje avance','Entrega','Recibe'])
    for r in data['units']:
        writer.writerow([r['code'],r['type_code'],r['detail'],r['nv'] or '',r['created_at'],r['received_at'] or '',r['status'],r['vb'],r['na'],r['pending'],r['progress'],r['deliverer_name'] or '',r['receiver_name'] or ''])
    return Response(output.getvalue().encode('utf-8'),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="UNIDAD360_reporte.csv"','Cache-Control':'no-store'})

@app.post('/api/units')
def units_create(payload:UnitNew,request:Request):
    actor=require_csrf(request)
    if payload.detail not in ('arriendo','stock','nv'):raise HTTPException(400,'Detalle inválido')
    with db() as c:
        if not c.execute('SELECT 1 FROM types WHERE id=? AND active=1',(payload.type_id,)).fetchone():raise HTTPException(400,'Tipo inválido')
        try:c.execute('INSERT INTO units(code,detail,type_id,nv,created_at,updated_at,observations) VALUES (?,?,?,?,?,?,?)',(payload.code.strip(),payload.detail,payload.type_id,payload.nv.strip() if payload.nv else None,now(),now(),payload.observations))
        except sqlite3.IntegrityError:raise HTTPException(409,'Ya existe esa combinación de código, tipo y detalle')
        uid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
        for row in c.execute('SELECT title,applies,position FROM template_items WHERE type_id=? ORDER BY position',(payload.type_id,)).fetchall():
            c.execute('INSERT INTO reviews(unit_id,title,position,state) VALUES (?,?,?,?)',(uid,row['title'],row['position'],'pendiente' if row['applies'] else 'na'))
        audit(c,uid,actor,'creación','Unidad registrada sin iniciar')
        return load_unit(c,uid)
@app.get('/api/units/{uid}')
def unit_detail(uid:int,request:Request):
    user_of(request)
    with db() as c:return load_unit(c,uid)
@app.patch('/api/units/{uid}')
def unit_update(uid:int,payload:UnitPatch,request:Request):
    actor=require_csrf(request)
    with db() as c:
        old=load_unit(c,uid)
        if old['received_at']:raise HTTPException(409,'Informe recibido y cerrado; no se puede modificar')
        c.execute('UPDATE units SET nv=?,observations=?,updated_at=? WHERE id=?',(payload.nv if payload.nv is not None else old['nv'],payload.observations if payload.observations is not None else old['observations'],now(),uid))
        audit(c,uid,actor,'edición','Datos generales u observaciones')
        return load_unit(c,uid)
@app.patch('/api/units/{uid}/reviews/{rid}')
def review_update(uid:int,rid:int,payload:ReviewPatch,request:Request):
    actor=require_csrf(request)
    if payload.state not in ('pendiente','vb','na'):raise HTTPException(400,'Estado inválido')
    with db() as c:
        old=load_unit(c,uid)
        if old['received_at']:raise HTTPException(409,'Informe recibido y cerrado')
        rev=c.execute('SELECT * FROM reviews WHERE id=? AND unit_id=?',(rid,uid)).fetchone()
        if not rev:raise HTTPException(404,'Control inexistente')
        c.execute('UPDATE reviews SET state=? WHERE id=?',(payload.state,rid))
        c.execute('UPDATE units SET started_at=COALESCE(started_at,?),updated_at=? WHERE id=?',(now(),now(),uid))
        audit(c,uid,actor,'revisión',f"{rev['title']}: {rev['state']} → {payload.state}")
        return load_unit(c,uid)
@app.post('/api/units/{uid}/responsible/{role}')
def assign_person(uid:int,role:str,payload:AttachPerson,request:Request):
    actor=require_csrf(request)
    if role not in ('trabajador','supervisor'):raise HTTPException(400,'Rol inválido')
    with db() as c:
        old=load_unit(c,uid)
        if old['received_at']:raise HTTPException(409,'Informe ya recibido')
        p=c.execute('SELECT * FROM people WHERE id=? AND role=? AND active=1',(payload.person_id,role)).fetchone()
        if not p:raise HTTPException(400,'Responsable incompatible')
        col='deliverer_id' if role=='trabajador' else 'receiver_id'
        c.execute(f'UPDATE units SET {col}=?,updated_at=? WHERE id=?',(p['id'],now(),uid))
        audit(c,uid,actor,'identificación',f"{role}: {p['name']} (asignado por usuario autenticado)")
        return load_unit(c,uid)
@app.post('/api/units/{uid}/receive')
def unit_receive(uid:int,request:Request):
    actor=require_csrf(request)
    with db() as c:
        d=load_unit(c,uid)
        if d['received_at']:raise HTTPException(409,'Unidad ya recibida')
        if not d['ready_to_receive']:raise HTTPException(409,'Para recibir: trabajador y supervisor identificados, revisión iniciada y todos los controles aplicables aprobados o N/A')
        stamp=now();c.execute('UPDATE units SET received_at=?,completed_at=?,updated_at=? WHERE id=?',(stamp,stamp,stamp,uid))
        audit(c,uid,actor,'recepción',f"Recepción registrada por usuario del sistema; supervisor asociado: {d['receiver_name']}")
        return load_unit(c,uid)
@app.post('/api/units/{uid}/photos')
async def photo_add(uid:int,request:Request,file:UploadFile=File(...)):
    actor=require_csrf(request)
    with db() as c:
        d=load_unit(c,uid)
        if d['received_at']:raise HTTPException(409,'Informe cerrado')
        if len(d['photos'])>=100:raise HTTPException(400,'Máximo 100 fotografías por informe')
    data=await file.read(8*1024*1024+1)
    if len(data)>8*1024*1024:raise HTTPException(413,'Fotografía supera 8 MB')
    try:
        im=Image.open(io.BytesIO(data));im.verify();im=Image.open(io.BytesIO(data));im=ImageOps.exif_transpose(im).convert('RGB');im.thumbnail((1800,1800))
    except Exception:raise HTTPException(400,'Archivo no es una imagen válida')
    filename=uuid.uuid4().hex+'.jpg';im.save(UPLOAD/filename,quality=85,optimize=True)
    with db() as c:
        c.execute('INSERT INTO photos(unit_id,filename,created_at) VALUES (?,?,?)',(uid,filename,now()))
        audit(c,uid,actor,'fotografía','Fotografía adjuntada')
        c.execute('UPDATE units SET updated_at=? WHERE id=?',(now(),uid))
        return load_unit(c,uid)
@app.patch('/api/units/{uid}/photos/{photo_id}')
def photo_edit(uid:int,photo_id:int,payload:PhotoCaption,request:Request):
    actor=require_csrf(request)
    with db() as c:
        d=load_unit(c,uid)
        if d['received_at']:raise HTTPException(409,'Informe cerrado')
        c.execute('UPDATE photos SET caption=? WHERE id=? AND unit_id=?',(payload.caption[:300],photo_id,uid))
        audit(c,uid,actor,'fotografía','Descripción modificada')
        return load_unit(c,uid)
@app.delete('/api/units/{uid}/photos/{photo_id}')
def photo_delete(uid:int,photo_id:int,request:Request):
    actor=require_csrf(request)
    with db() as c:
        d=load_unit(c,uid)
        if d['received_at']:raise HTTPException(409,'Informe cerrado')
        row=c.execute('SELECT * FROM photos WHERE id=? AND unit_id=?',(photo_id,uid)).fetchone()
        if not row:raise HTTPException(404,'Fotografía inexistente')
        c.execute('DELETE FROM photos WHERE id=?',(photo_id,))
        audit(c,uid,actor,'fotografía','Fotografía eliminada')
    (UPLOAD/row['filename']).unlink(missing_ok=True)
    return {'ok':True}
@app.get('/api/photos/{photo_id}/file')
def photo_file(photo_id:int,request:Request):
    user_of(request)
    with db() as c:row=c.execute('SELECT filename FROM photos WHERE id=?',(photo_id,)).fetchone()
    if not row:raise HTTPException(404,'Sin fotografía')
    return FileResponse(UPLOAD/row['filename'])

from pdf_report import build_pdf as render_pdf, image_fit as pdf_image

def build_pdf(d):
    return render_pdf(d,QR_DIR,UPLOAD,now())

@app.get('/api/units/{uid}/pdf')
def get_pdf(uid:int,request:Request):
    user_of(request)
    with db() as c:d=load_unit(c,uid)
    filename=re.sub(r'[^A-Za-z0-9_-]+','_',f"informe_{d['code']}_{d['type_code']}")+'.pdf'
    return StreamingResponse(build_pdf(d),media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="{filename}"','Cache-Control':'no-store'})

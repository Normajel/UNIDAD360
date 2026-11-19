"""UNIDAD360 cloud API, independent of local SQLite. Import from cloud_app:app.

No privileged Supabase service key is used. Every request is authenticated as
an admin via Supabase Auth and PostgREST/Storage are accessed using that JWT.
"""
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
import qrcode
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from PIL import Image, ImageOps
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from xml.sax.saxutils import escape

from pdf_report import build_pdf as render_pdf, image_fit as pdf_image

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / '.env')
URL = os.environ.get('SUPABASE_URL', '').rstrip('/')
KEY = os.environ.get('SUPABASE_KEY', '')
SESSION_SECRET = os.environ.get('UNIDAD360_SESSION_SECRET', '')
ADMIN_EMAIL = os.environ.get('UNIDAD360_ADMIN_EMAIL', '')
BUCKET = 'unidad360-evidence'
SESSION_MAX_AGE = 50 * 60  # Short-lived session; no sensitive refresh token in cookie.
COOKIE = 'unidad360_cloud_session'
SECRET_IS_READY = len(SESSION_SECRET) >= 32
SIGNER = URLSafeTimedSerializer(SESSION_SECRET) if SECRET_IS_READY else None
STATIC = ROOT / 'cloud_static'
app = FastAPI(title='UNIDAD360 Cloud', version='3.0.0')
if STATIC.is_dir():
    app.mount('/static', StaticFiles(directory=STATIC), name='static')


def require_config():
    if not (URL.startswith('https://') and KEY and SECRET_IS_READY and ADMIN_EMAIL):
        raise HTTPException(503, 'Configuración cloud incompleta')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def api_headers(token, content_type=True):
    h = {'apikey': KEY, 'Authorization': f'Bearer {token}'}
    if content_type:
        h['Content-Type'] = 'application/json'
    return h


def remote(method, path, token, *, params=None, payload=None, data=None, headers=None, storage=False):
    base = URL + ('/storage/v1' if storage else '/rest/v1')
    target = base + path
    opts = dict(headers=api_headers(token, not storage), params=params, timeout=45, follow_redirects=False)
    if headers:
        opts['headers'].update(headers)
    if payload is not None:
        opts['json'] = payload
    if data is not None:
        opts['content'] = data
    try:
        with httpx.Client() as client:
            r = client.request(method, target, **opts)
    except httpx.RequestError as ex:
        raise HTTPException(502, 'No fue posible conectar a Supabase') from ex
    if r.status_code >= 400:
        try:
            msg = r.json().get('message') or r.json().get('error') or 'Error Supabase'
            code = r.json().get('code')
        except ValueError:
            msg, code = 'Error Supabase', None
        status = 409 if r.status_code in (400, 409, 422) or code in ('23505', '23514', 'P0001') else r.status_code
        if status >= 500:
            status = 502
        raise HTTPException(status, str(msg)[:220])
    if r.status_code == 204 or not r.content:
        return []
    if 'json' in r.headers.get('content-type', ''):
        return r.json()
    return r.content


def select(table, token, *, cols='*', where=None, order=None, limit=1000):
    params = {'select': cols, 'limit': str(limit)}
    if where:
        params.update(where)
    if order:
        params['order'] = order
    return remote('GET', '/' + table, token, params=params)


def select_all(table, token, *, cols='*', where=None, order='id.asc', batch_size=500):
    """Paginate full exports; never return a silently truncated backup."""
    rows = []
    offset = 0
    while True:
        params = {'select': cols, 'limit': str(batch_size), 'offset': str(offset)}
        if where:
            params.update(where)
        if order:
            params['order'] = order
        page = remote('GET', '/' + table, token, params=params)
        if not isinstance(page, list):
            raise HTTPException(502, 'Respuesta inesperada al exportar ' + table)
        rows.extend(page)
        if len(page) < batch_size:
            return rows
        offset += batch_size
        if offset > 1_000_000:
            raise HTTPException(507, 'Exportación demasiado grande; utilizar respaldos administrados')


def single(table, token, rid):
    rows = select(table, token, where={'id': 'eq.' + str(rid)}, limit=1)
    if not rows:
        raise HTTPException(404, 'Registro inexistente')
    return rows[0]


def put(table, token, data):
    rows = remote('POST', '/' + table, token, payload=data, headers={'Prefer': 'return=representation'})
    return rows[0] if isinstance(data, dict) else rows


def patch(table, token, rid, data):
    result = remote('PATCH', '/' + table, token, params={'id': 'eq.' + str(rid)}, payload=data,
                    headers={'Prefer': 'return=representation'})
    if not result:
        raise HTTPException(409, 'Registro no actualizado')
    return result[0]


def remove(table, token, rid):
    remote('DELETE', '/' + table, token, params={'id': 'eq.' + str(rid)})


def jwt_for(request: Request):
    require_config()
    signed = request.cookies.get(COOKIE, '')
    if not signed:
        raise HTTPException(401, 'Debes iniciar sesión')
    try:
        token = SIGNER.loads(signed, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, 'Sesión vencida; ingresa nuevamente')
    if not isinstance(token, str) or len(token) > 8192:
        raise HTTPException(401, 'Sesión inválida')
    return token


def admin(request: Request, *, mutate=False):
    token = jwt_for(request)
    # Must always verify admin membership; don't trust client cookies alone.
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.get(URL + '/auth/v1/user', headers=api_headers(token))
        if resp.status_code != 200:
            raise HTTPException(401, 'Sesión inválida')
        uid = resp.json()['id']
        member = select('unidad360_admins', token, cols='user_id', where={'user_id': 'eq.' + uid}, limit=1)
        if not member:
            raise HTTPException(403, 'Acceso restringido al administrador')
    except (httpx.RequestError, ValueError, KeyError) as exc:
        raise HTTPException(502, 'No se pudo verificar la sesión') from exc
    if mutate:
        csrf = request.headers.get('X-CSRF-Token', '')
        expected = hmac.new(SESSION_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(csrf, expected):
            raise HTTPException(403, 'Token CSRF inválido')
        origin = request.headers.get('origin')
        if origin:
            # Proxies serverless may present an internal HTTP scheme even when the
            # public browser origin is HTTPS. Use an explicitly configured,
            # trusted canonical origin when deployed, not untrusted forwarded headers.
            allowed = os.environ.get('UNIDAD360_PUBLIC_ORIGIN', '').rstrip('/')
            if not allowed:
                allowed = str(request.base_url).rstrip('/')
            if origin != allowed:
                raise HTTPException(403, 'Origen de solicitud incorrecto')
    return token, uid


def secure_cookie(request):
    return os.environ.get('UNIDAD360_HTTPS', '0') == '1' or request.url.scheme == 'https'


def session_csrf(token):
    return hmac.new(SESSION_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()


class Login(BaseModel):
    username: str
    password: str


class UnitNew(BaseModel):
    code: str = Field(min_length=1, max_length=100)
    detail: str
    type_id: str
    nv: str | None = ''
    observations: str = ''


class UnitPatch(BaseModel):
    nv: str | None = None
    observations: str | None = None


class ReviewPatch(BaseModel):
    state: str


class AttachPerson(BaseModel):
    person_id: str


class TypeNew(BaseModel):
    code: str = Field(min_length=2, max_length=80)
    category: str = ''


class TemplatePatch(BaseModel):
    items: list[dict]


class TemplateCopy(BaseModel):
    source_type_id: str


class PersonNew(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    role: str
    rut: str = Field(min_length=8, max_length=16)
    position: str = Field(min_length=2, max_length=100)


class QrLookup(BaseModel):
    value: str = Field(min_length=8, max_length=300)


class PhotoCaption(BaseModel):
    caption: str = ''


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@app.get('/')
def home():
    if not (STATIC / 'index.html').is_file():
        raise HTTPException(503, 'Ejecuta primero preparar_interfaz_cloud.py')
    return FileResponse(STATIC / 'index.html')


@app.post('/api/login')
def login(payload: Login, request: Request):
    require_config()
    username = payload.username.strip().lower()
    # Preserve existing 'admin' login while authenticating with real Supabase email.
    email = ADMIN_EMAIL if username == 'admin' else username
    if email.lower() != ADMIN_EMAIL.lower():
        raise HTTPException(401, 'Credenciales incorrectas')
    try:
        with httpx.Client(timeout=25) as client:
            r = client.post(URL + '/auth/v1/token', params={'grant_type': 'password'},
                            headers={'apikey': KEY, 'Content-Type': 'application/json'},
                            json={'email': email, 'password': payload.password})
    except httpx.RequestError as exc:
        raise HTTPException(502, 'Supabase Auth no responde') from exc
    if r.status_code != 200:
        raise HTTPException(401, 'Credenciales incorrectas o se requiere CAPTCHA')
    session = r.json()
    token = session.get('access_token', '')
    if not token:
        raise HTTPException(401, 'Sesión de Auth no disponible')
    # Verify admin RLS with this newly issued token before setting the cookie.
    with httpx.Client(timeout=20) as client:
        identity = client.get(URL + '/auth/v1/user', headers=api_headers(token))
    if identity.status_code != 200:
        raise HTTPException(401, 'No se pudo verificar la identidad')
    user_id = identity.json().get('id', '')
    if not select('unidad360_admins', token, cols='user_id', where={'user_id': 'eq.' + user_id}, limit=1):
        raise HTTPException(403, 'No es administrador de UNIDAD360')
    response = Response(content=json.dumps({'username': 'admin', 'csrf': session_csrf(token)}), media_type='application/json')
    response.set_cookie(COOKIE, SIGNER.dumps(token), max_age=SESSION_MAX_AGE, secure=secure_cookie(request),
                        httponly=True, samesite='strict', path='/')
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/api/me')
def me(request: Request):
    token, _ = admin(request)
    return {'username': 'admin', 'csrf': session_csrf(token)}


@app.post('/api/logout')
def logout(request: Request):
    admin(request, mutate=True)
    resp = Response(status_code=204)
    resp.delete_cookie(COOKIE, path='/')
    return resp


def audit(token, uid, action, detail, actor):
    # Historical audit rows remain unattributed to current admin; new ones use auth user ID.
    try:
        put('unit_audit', token, {'actor_user_id': actor, 'entity_type': 'unit' if uid else 'system',
                                  'entity_id': uid, 'unit_id': uid, 'action': action,
                                  'detail': {'text': detail, 'source': 'cloud'}})
    except HTTPException:
        # Must not falsely imply successful audited mutations; caller handles if important.
        raise


def norm_type(t):
    return {'id': t['id'], 'code': t['code'], 'category': t.get('category', ''), 'active': t.get('active', True)}


def norm_person(p):
    return {'id': p['id'], 'name': p['full_name'], 'position': p.get('position') or '',
            'rut': p.get('rut') or '', 'role': 'trabajador' if p['role'] == 'worker' else 'supervisor',
            'active': p['active'], 'qr_value': p.get('qr_value') or '',
            'qr_filename': p.get('qr_filename') or p.get('qr_storage_path') or ''}


def unit_record(token, unit, *, batch=None):
    """Formato de ficha idéntico; batch evita N+1 solicitudes en listados."""
    uid = unit['id']
    if batch is None:
        tp = single('unit_types', token, unit['unit_type_id'])
        all_people = select('responsibles', token)
        reviews = select('unit_reviews', token, where={'unit_id': 'eq.' + uid}, order='position.asc')
        photos = select('unit_photos', token, where={'unit_id': 'eq.' + uid}, order='created_at.asc')
        audit_rows = select('unit_audit', token, where={'unit_id': 'eq.' + uid}, order='created_at.desc', limit=60)
    else:
        tp = batch['types'][unit['unit_type_id']]
        all_people = batch['people']
        reviews = batch['reviews'].get(uid, [])
        photos = batch['photos'].get(uid, [])
        # Los listados nunca incluyen auditoría; se consulta al abrir una ficha.
        audit_rows = []
    persons = {p['id']: norm_person(p) for p in all_people}
    deliverer = persons.get(unit.get('worker_id'), {})
    receiver = persons.get(unit.get('supervisor_id'), {})
    review_view = [{'id': r['id'], 'title': r['label'], 'position': r['position'],
                    'state': r['status']} for r in reviews]
    photo_view = [{'id': p['id'], 'filename': p['storage_path'].split('/')[-1],
                   'storage_path': p['storage_path'], 'caption': p.get('description') or '',
                   'created_at': p['created_at']} for p in photos]
    audit_view = [{'id': a['id'], 'action': a['action'], 'detail': a.get('legacy_detail') or
                   (a.get('detail') or {}).get('text', '') if isinstance(a.get('detail'), dict) else str(a.get('detail') or ''), 'actor': a.get('legacy_actor') or 'Administrador',
                   'created_at': a['created_at']} for a in audit_rows]
    pending = sum(r['state'] == 'pending' or r['state'] == 'pendiente' for r in review_view)
    vb = sum(r['state'] == 'vb' for r in review_view)
    na = sum(r['state'] == 'na' for r in review_view)
    # Handle Supabase canonical status 'pending' but expose original UI status 'pendiente'.
    for r in review_view:
        if r['state'] == 'pending':
            r['state'] = 'pendiente'
    total = len(review_view)
    applicable = total - na
    completed_at = unit.get('received_at') or unit.get('legacy_receipt_at')
    started = unit.get('review_started_at')
    status = 'finalizada' if completed_at else ('pendiente' if started else 'no_iniciada')
    ready = bool(not completed_at and started and pending == 0 and applicable > 0 and
                 unit.get('worker_id') and unit.get('supervisor_id'))
    d = dict(unit)
    d.update(type_id=tp['id'], type_code=tp['code'], detail=(unit.get('category') or '').lower(),
             nv=unit.get('nv_number') or '', observations=unit.get('notes') or '',
             started_at=started, completed_at=unit.get('received_at') or unit.get('legacy_completed_at'),
             received_at=completed_at, deliverer_id=unit.get('worker_id'), receiver_id=unit.get('supervisor_id'),
             deliverer_name=deliverer.get('name'), deliverer_position=deliverer.get('position'),
             deliverer_rut=deliverer.get('rut'), deliverer_qr=deliverer.get('qr_filename'),
             receiver_name=receiver.get('name'), receiver_position=receiver.get('position'),
             receiver_rut=receiver.get('rut'), receiver_qr=receiver.get('qr_filename'),
             reviews=review_view, photos=photo_view, audit=audit_view,
             pending=pending, vb=vb, na=na, total=total, progress=round(vb / applicable * 100) if applicable else 0,
             status=status, ready_to_receive=ready)
    return d


def all_units(token):
    """Carga por lotes, manteniendo autorización RLS en cada consulta."""
    units = select_all('units', token, order='created_at.desc')
    if not units:
        return []
    types_by_id = {t['id']: t for t in select('unit_types', token)}
    people_rows = select('responsibles', token)
    reviews_by_unit = {}
    for r in select_all('unit_reviews', token, order='position.asc'):
        reviews_by_unit.setdefault(r['unit_id'], []).append(r)
    photos_by_unit = {}
    for photo in select_all('unit_photos', token, order='created_at.asc'):
        photos_by_unit.setdefault(photo['unit_id'], []).append(photo)
    batch = {'types': types_by_id, 'people': people_rows,
             'reviews': reviews_by_unit, 'photos': photos_by_unit}
    return [unit_record(token, u, batch=batch) for u in units]


@app.get('/api/bootstrap')
def bootstrap(request: Request):
    """Carga inicial del panel: una sola comprobación Auth/RLS."""
    token, _ = admin(request)
    return {
        'types': [norm_type(t) for t in select('unit_types', token, where={'active': 'eq.true'}, order='code.asc')],
        'people': [norm_person(p) for p in select('responsibles', token, order='active.desc,full_name.asc')],
        'units': all_units(token),
    }


@app.get('/api/types')
def types(request: Request):
    token, _ = admin(request)
    return [norm_type(t) for t in select('unit_types', token, where={'active': 'eq.true'}, order='code.asc')]


@app.post('/api/types')
def create_type(payload: TypeNew, request: Request):
    token, actor = admin(request, mutate=True)
    code = payload.code.strip().upper()
    if not code:
        raise HTTPException(400, 'Código requerido')
    new = put('unit_types', token, {'code': code, 'category': payload.category.strip() or 'Catálogo inicial'})
    # Default checklist can be customized; do not assume every new type matches old standard.
    audit(token, None, 'creación_tipo', code, actor)
    return {'id': new['id']}


@app.get('/api/types/{type_id}/template')
def template(type_id: uuid.UUID, request: Request):
    token, _ = admin(request)
    return [{'id': i['id'], 'title': i['label'], 'applies': i['applies'], 'position': i['position']}
            for i in select('unit_template_items', token, where={'unit_type_id': 'eq.' + str(type_id)}, order='position.asc')]


@app.put('/api/types/{type_id}/template')
def save_template(type_id: uuid.UUID, payload: TemplatePatch, request: Request):
    token, actor = admin(request, mutate=True)
    if not 1 <= len(payload.items) <= 100 or not any(bool(x.get('applies', True)) for x in payload.items):
        raise HTTPException(400, 'La plantilla requiere al menos un control aplicable, máximo 100')
    titles = [str(x.get('title', '')).strip() for x in payload.items]
    if any(not x or len(x) > 180 for x in titles) or len(set(titles)) != len(titles):
        raise HTTPException(400, 'Controles vacíos o duplicados')
    data = [{'label': title, 'applies': bool(payload.items[i].get('applies', True)), 'position': i}
            for i, title in enumerate(titles)]
    remote('POST', '/rpc/unidad360_replace_template', token,
           payload={'p_type_id': str(type_id), 'p_items': data})
    audit(token, None, 'plantilla', f'{type_id}', actor)
    return {'ok': True, 'note': 'Plantilla actualizada; las unidades existentes no cambian.'}


@app.post('/api/types/{type_id}/template/copy')
def copy_template(type_id: uuid.UUID, payload: TemplateCopy, request: Request):
    token, actor = admin(request, mutate=True)
    src = select('unit_template_items', token, where={'unit_type_id': 'eq.' + str(payload.source_type_id)}, order='position.asc')
    if not src:
        raise HTTPException(404, 'Plantilla de origen sin controles')
    if str(type_id) == str(payload.source_type_id):
        raise HTTPException(400, 'Tipo de origen y destino iguales')
    return save_template(type_id, TemplatePatch(items=[{'title': r['label'], 'applies': r['applies']} for r in src]), request)


def valid_rut(value):
    raw = re.sub(r'[.\-\s]', '', value).upper()
    if not re.fullmatch(r'\d{7,8}[0-9K]', raw):
        raise HTTPException(400, 'RUT inválido')
    total = 0
    mul = 2
    for digit in reversed(raw[:-1]):
        total += int(digit) * mul
        mul = 2 if mul == 7 else mul + 1
    k = 11 - total % 11
    expected = '0' if k == 11 else 'K' if k == 10 else str(k)
    if expected != raw[-1]:
        raise HTTPException(400, 'Dígito verificador de RUT incorrecto')
    return raw[:-1] + '-' + raw[-1]


@app.get('/api/people')
def people(request: Request):
    token, _ = admin(request)
    return [norm_person(p) for p in select('responsibles', token, order='active.desc,full_name.asc')]


def qr_bytes(value):
    b = io.BytesIO()
    qrcode.make(value, box_size=10, border=3).save(b, format='PNG')
    return b.getvalue()


def storage_upload(token, path, payload, content_type):
    return remote('POST', '/object/' + BUCKET + '/' + quote(path, safe='/'), token, data=payload,
                  headers={'Content-Type': content_type, 'x-upsert': 'false'}, storage=True)


def storage_download(token, path):
    return remote('GET', '/object/authenticated/' + BUCKET + '/' + quote(path, safe='/'), token, storage=True)


@app.post('/api/people')
def person_create(payload: PersonNew, request: Request):
    token, actor = admin(request, mutate=True)
    if payload.role not in ('trabajador', 'supervisor'):
        raise HTTPException(400, 'Rol incorrecto')
    rut = valid_rut(payload.rut)
    qr_val = 'RESP-' + secrets.token_hex(16).upper()
    identifier = str(uuid.uuid4())
    path = f'qr/{identifier}.png'
    storage_upload(token, path, qr_bytes(qr_val), 'image/png')
    try:
        row = put('responsibles', token, {'id': identifier, 'full_name': payload.name.strip(),
               'role': 'worker' if payload.role == 'trabajador' else 'supervisor',
               'position': payload.position.strip(), 'rut': rut, 'qr_value': qr_val,
               'qr_filename': identifier + '.png', 'qr_storage_path': path})
    except Exception:
        try:
            remote('DELETE', '/object/' + BUCKET, token, payload={'prefixes': [path]}, storage=True)
        except Exception:
            pass
        raise
    audit(token, None, 'responsable', 'Nuevo responsable creado', actor)
    return {'id': row['id'], 'message': 'Responsable y QR registrados'}


@app.put('/api/people/{pid}')
def person_edit(pid: uuid.UUID, payload: PersonNew, request: Request):
    token, actor = admin(request, mutate=True)
    person = single('responsibles', token, str(pid))
    role = 'worker' if payload.role == 'trabajador' else 'supervisor'
    used = select('units', token, cols='id', where={'or': f'(worker_id.eq.{pid},supervisor_id.eq.{pid})'}, limit=1)
    if used and person['role'] != role:
        raise HTTPException(409, 'Rol ya utilizado; no puede cambiarse')
    patch('responsibles', token, str(pid), {'full_name': payload.name.strip(), 'position': payload.position.strip(),
           'rut': valid_rut(payload.rut), 'role': role})
    audit(token, None, 'responsable', 'Responsable editado', actor)
    return {'ok': True}


@app.post('/api/people/{pid}/deactivate')
def person_disable(pid: uuid.UUID, request: Request):
    token, actor = admin(request, mutate=True)
    patch('responsibles', token, str(pid), {'active': False})
    audit(token, None, 'responsable', 'Responsable desactivado', actor)
    return {'ok': True}


@app.post('/api/people/{pid}/activate')
def person_enable(pid: uuid.UUID, request: Request):
    token, actor = admin(request, mutate=True)
    patch('responsibles', token, str(pid), {'active': True})
    audit(token, None, 'responsable', 'Responsable reactivado', actor)
    return {'ok': True}


@app.delete('/api/people/{pid}')
def person_delete(pid: uuid.UUID, request: Request):
    token, actor = admin(request, mutate=True)
    used = select('units', token, cols='id', where={'or': f'(worker_id.eq.{pid},supervisor_id.eq.{pid})'}, limit=1)
    if used:
        raise HTTPException(409, 'Responsable usado en recepciones; solo se puede desactivar')
    person = single('responsibles', token, str(pid))
    remove('responsibles', token, str(pid))
    audit(token, None, 'responsable', 'Responsable eliminado', actor)
    # Retain old QR file until next maintenance to avoid orphan reversal races.
    return {'ok': True}


@app.post('/api/people/resolve-qr')
def qr_lookup(payload: QrLookup, request: Request):
    token, _ = admin(request, mutate=True)
    rows = select('responsibles', token, where={'qr_value': 'eq.' + payload.value.strip(), 'active': 'eq.true'}, limit=1)
    if not rows:
        raise HTTPException(404, 'QR inexistente o responsable inactivo')
    return norm_person(rows[0])


@app.get('/api/people/{pid}/qr-image')
def qr_image(pid: uuid.UUID, request: Request):
    token, _ = admin(request)
    p = single('responsibles', token, str(pid))
    # Render directly from the stable, private QR value. No filesystem reliance.
    return Response(qr_bytes(p['qr_value']), media_type='image/png', headers={'Cache-Control': 'no-store'})


@app.get('/api/people/{pid}/credential')
def credential(pid: uuid.UUID, request: Request):
    token, _ = admin(request)
    p = norm_person(single('responsibles', token, str(pid)))
    with tempfile.TemporaryDirectory() as d:
        img = Path(d) / 'qr.png'
        img.write_bytes(qr_bytes(p['qr_value']))
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=25 * mm, rightMargin=25 * mm)
        styles = getSampleStyleSheet()
        flow = [Paragraph('CREDENCIAL DE RESPONSABLE', styles['Heading1']), Spacer(1, 15),
                Paragraph(escape(p['name']), styles['Heading2']),
                Paragraph('Cargo: ' + escape(p['position']), styles['Normal']),
                Paragraph('RUT: ' + escape(p['rut']), styles['Normal']),
                Paragraph('Rol: ' + ('ENTREGA' if p['role'] == 'trabajador' else 'RECEPCIÓN'), styles['Normal']),
                Spacer(1, 15), pdf_image(img, 65 * mm, 65 * mm), Spacer(1, 10),
                Paragraph('QR interno, no reemplaza firma ni autenticación.', styles['Normal'])]
        doc.build(flow)
    return Response(buf.getvalue(), media_type='application/pdf', headers={'Cache-Control': 'no-store'})


@app.get('/api/units')
def units(request: Request, q: str = '', status: str = '', type_id: str = '', detail: str = '', date_from: str = '', date_to: str = ''):
    token, _ = admin(request)
    records = all_units(token)
    if type_id:
        records = [r for r in records if r['type_id'] == type_id]
    if detail:
        records = [r for r in records if r['detail'] == detail]
    if date_from:
        records = [r for r in records if r['created_at'][:10] >= date_from]
    if date_to:
        records = [r for r in records if r['created_at'][:10] <= date_to]
    if status:
        records = [r for r in records if r['status'] == status]
    if q:
        search = q.casefold()
        records = [r for r in records if search in (r['code'] + r['type_code'] + r['nv'] + r['detail']).casefold()]
    for r in records:
        r.pop('audit', None)
    return records


@app.get('/api/units/{uid}')
def unit_detail(uid: uuid.UUID, request: Request):
    token, _ = admin(request)
    return unit_record(token, single('units', token, str(uid)))


@app.post('/api/units')
def unit_create(payload: UnitNew, request: Request):
    token, actor = admin(request, mutate=True)
    if payload.detail not in ('stock', 'arriendo', 'nv'):
        raise HTTPException(400, 'Detalle inválido')
    record = remote('POST', '/rpc/unidad360_create_unit', token,
                    payload={'p_code': payload.code.strip(), 'p_category': payload.detail.title() if payload.detail != 'nv' else 'NV',
                             'p_type_id': payload.type_id, 'p_nv': payload.nv or None,
                             'p_notes': payload.observations or ''})
    return unit_record(token, single('units', token, record))


@app.patch('/api/units/{uid}')
def unit_edit(uid: uuid.UUID, payload: UnitPatch, request: Request):
    token, actor = admin(request, mutate=True)
    d = unit_record(token, single('units', token, str(uid)))
    if d['received_at']:
        raise HTTPException(409, 'Unidad recibida no editable')
    data = {}
    if payload.nv is not None:
        data['nv_number'] = payload.nv
    if payload.observations is not None:
        data['notes'] = payload.observations
    if data:
        patch('units', token, str(uid), data)
        audit(token, str(uid), 'edición', 'Datos generales modificados', actor)
    return unit_record(token, single('units', token, str(uid)))


@app.patch('/api/units/{uid}/reviews/{rid}')
def review_edit(uid: uuid.UUID, rid: uuid.UUID, payload: ReviewPatch, request: Request):
    token, actor = admin(request, mutate=True)
    if payload.state not in ('pendiente', 'vb', 'na'):
        raise HTTPException(400, 'Estado inválido')
    result = remote('POST', '/rpc/unidad360_set_review', token,
                    payload={'p_unit_id': str(uid), 'p_review_id': str(rid), 'p_status': 'pending' if payload.state == 'pendiente' else payload.state})
    return unit_record(token, single('units', token, str(uid)))


@app.post('/api/units/{uid}/responsible/{role}')
def assign_person(uid: uuid.UUID, role: str, payload: AttachPerson, request: Request):
    token, actor = admin(request, mutate=True)
    if role not in ('trabajador', 'supervisor'):
        raise HTTPException(400, 'Rol inválido')
    remote('POST', '/rpc/unidad360_assign_responsible', token,
           payload={'p_unit_id': str(uid), 'p_person_id': payload.person_id, 'p_role': 'worker' if role == 'trabajador' else 'supervisor'})
    return unit_record(token, single('units', token, str(uid)))


@app.post('/api/units/{uid}/receive')
def unit_receive(uid: uuid.UUID, request: Request):
    token, actor = admin(request, mutate=True)
    remote('POST', '/rpc/unidad360_receive_unit', token, payload={'p_unit_id': str(uid)})
    return unit_record(token, single('units', token, str(uid)))


@app.post('/api/units/{uid}/photos')
async def photo_add(uid: uuid.UUID, request: Request, file: UploadFile = File(...)):
    token, actor = admin(request, mutate=True)
    d = unit_record(token, single('units', token, str(uid)))
    if d['received_at']:
        raise HTTPException(409, 'Informe cerrado')
    if len(d['photos']) >= 100:
        raise HTTPException(400, 'Máximo 100 fotografías')
    content = await file.read(8 * 1024 * 1024 + 1)
    if len(content) > 8 * 1024 * 1024:
        raise HTTPException(413, 'Fotografía demasiado grande')
    try:
        im = Image.open(io.BytesIO(content))
        im.verify()
        im = Image.open(io.BytesIO(content))
        im = ImageOps.exif_transpose(im).convert('RGB')
        im.thumbnail((1800, 1800))
    except Exception as exc:
        raise HTTPException(400, 'Imagen inválida') from exc
    buffer = io.BytesIO()
    im.save(buffer, 'JPEG', quality=85, optimize=True)
    name = str(uuid.uuid4()) + '.jpg'
    path = f'photos/{uid}/{name}'
    storage_upload(token, path, buffer.getvalue(), 'image/jpeg')
    try:
        put('unit_photos', token, {'unit_id': str(uid), 'storage_path': path, 'description': ''})
    except Exception:
        # Orphan object can be removed during cleanup; don't risk deleting a valid evidence file on races.
        raise
    audit(token, str(uid), 'fotografía', 'Fotografía agregada', actor)
    return unit_record(token, single('units', token, str(uid)))


@app.patch('/api/units/{uid}/photos/{photo_id}')
def photo_edit(uid: uuid.UUID, photo_id: uuid.UUID, payload: PhotoCaption, request: Request):
    token, actor = admin(request, mutate=True)
    photo = single('unit_photos', token, str(photo_id))
    if photo['unit_id'] != str(uid):
        raise HTTPException(404, 'Fotografía inexistente')
    patch('unit_photos', token, str(photo_id), {'description': payload.caption[:300]})
    audit(token, str(uid), 'fotografía', 'Descripción modificada', actor)
    return unit_record(token, single('units', token, str(uid)))


@app.delete('/api/units/{uid}/photos/{photo_id}')
def photo_delete(uid: uuid.UUID, photo_id: uuid.UUID, request: Request):
    token, actor = admin(request, mutate=True)
    photo = single('unit_photos', token, str(photo_id))
    if photo['unit_id'] != str(uid):
        raise HTTPException(404, 'Fotografía inexistente')
    remove('unit_photos', token, str(photo_id))
    audit(token, str(uid), 'fotografía', 'Foto quitada de informe', actor)
    # Retain Storage object for forensic recovery; deletion managed separately.
    return {'ok': True}


@app.get('/api/photos/{photo_id}/file')
def photo_file(photo_id: uuid.UUID, request: Request):
    token, _ = admin(request)
    photo = single('unit_photos', token, str(photo_id))
    data = storage_download(token, photo['storage_path'])
    return Response(data, media_type='image/jpeg', headers={'Cache-Control': 'private, no-store'})


def report_data(token, date_from='', date_to='', type_id='', detail=''):
    all_records = all_units(token)
    rows = [d for d in all_records if (not date_from or d['created_at'][:10] >= date_from)
            and (not date_to or d['created_at'][:10] <= date_to)
            and (not type_id or d['type_id'] == type_id) and (not detail or d['detail'] == detail)]
    counts = {s: sum(d['status'] == s for d in rows) for s in ('finalizada', 'pendiente', 'no_iniciada')}
    details = {s: sum(d['detail'] == s for d in rows) for s in ('arriendo', 'stock', 'nv')}
    models, months = {}, {}
    for d in rows:
        k = d['type_code']
        m = models.setdefault(k, {'type_code': k, 'total': 0, 'finalizada': 0, 'pendiente': 0, 'no_iniciada': 0})
        m['total'] += 1
        m[d['status']] += 1
        k = d['created_at'][:7]
        x = months.setdefault(k, {'month': k, 'total': 0, 'received': 0})
        x['total'] += 1
        x['received'] += bool(d['received_at'])
    out = []
    for d in rows:
        out.append({'id': d['id'], 'code': d['code'], 'detail': d['detail'], 'type_code': d['type_code'],
                    'type_id': d['type_id'], 'nv': d['nv'], 'created_at': d['created_at'],
                    'received_at': d['received_at'], 'status': d['status'], 'pending': d['pending'],
                    'vb': d['vb'], 'na': d['na'], 'progress': d['progress'],
                    'deliverer_name': d['deliverer_name'], 'receiver_name': d['receiver_name']})
    return {'filters': dict(date_from=date_from, date_to=date_to, type_id=type_id, detail=detail),
            'totals': {'total': len(rows), **counts,
                       'percentage_finalized': round(counts['finalizada'] * 100 / len(rows)) if rows else 0,
                       'pending_checks': sum(d['pending'] for d in rows if not d['received_at']),
                       'awaiting_reception': sum(d['pending'] == 0 and d['started_at'] and not d['received_at'] for d in rows)},
            'by_detail': details, 'by_type': sorted(models.values(), key=lambda x: (-x['total'], x['type_code'])),
            'by_month': sorted(months.values(), key=lambda x: x['month']), 'units': out}


@app.get('/api/dashboard/summary')
def dashboard(request: Request):
    token, _ = admin(request)
    rows = all_units(token)
    counts = {s: sum(d['status'] == s for d in rows) for s in ('finalizada', 'pendiente', 'no_iniciada')}
    return {**counts, 'total': len(rows), 'ready_for_reception': sum(d['ready_to_receive'] for d in rows),
            'pending_checks': sum(d['pending'] for d in rows if not d['received_at']),
            'completed_without_reception': sum(d['pending'] == 0 and d['started_at'] and not d['received_at'] for d in rows),
            'percentage_finalized': round(counts['finalizada'] * 100 / len(rows)) if rows else 0}


@app.get('/api/reports/summary')
def report_summary(request: Request, date_from: str = '', date_to: str = '', type_id: str = '', detail: str = ''):
    token, _ = admin(request)
    return report_data(token, date_from, date_to, type_id, detail)


@app.get('/api/reports/export.csv')
def report_csv(request: Request, date_from: str = '', date_to: str = '', type_id: str = '', detail: str = ''):
    token, _ = admin(request)
    data = report_data(token, date_from, date_to, type_id, detail)
    output = io.StringIO(newline='')
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Código', 'Tipo', 'Detalle', 'NV', 'Creación', 'Recepción', 'Estado', 'V°B°', 'N/A', 'Pendientes', 'Avance', 'Entrega', 'Recibe'])
    for x in data['units']:
        writer.writerow([x['code'], x['type_code'], x['detail'], x['nv'], x['created_at'],
                         x['received_at'] or '', x['status'], x['vb'], x['na'], x['pending'], x['progress'],
                         x['deliverer_name'] or '', x['receiver_name'] or ''])
    return Response(output.getvalue().encode('utf-8'), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="UNIDAD360_reporte.csv"', 'Cache-Control': 'no-store'})


@app.get('/api/units/{uid}/pdf')
def pdf(uid: uuid.UUID, request: Request):
    token, _ = admin(request)
    d = unit_record(token, single('units', token, str(uid)))
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        photos = base / 'photos'
        qr_dir = base / 'qr'
        photos.mkdir()
        qr_dir.mkdir()
        for item in d['photos']:
            (photos / item['filename']).write_bytes(storage_download(token, item['storage_path']))
        for label in ('deliverer', 'receiver'):
            pid = d.get(label + '_id')
            if pid:
                person = single('responsibles', token, pid)
                name = str(pid) + '.png'
                (qr_dir / name).write_bytes(qr_bytes(person['qr_value']))
                d[label + '_qr'] = name
        document = render_pdf(d, qr_dir, photos, now()).getvalue()
    filename = re.sub(r'[^A-Za-z0-9_-]+', '_', f"informe_{d['code']}_{d['type_code']}") + '.pdf'
    return Response(document, media_type='application/pdf',
                    headers={'Content-Disposition': f'inline; filename="{filename}"', 'Cache-Control': 'no-store'})


@app.post('/api/admin/change-password')
def change_password(payload: PasswordChange, request: Request):
    token, actor = admin(request, mutate=True)
    if len(payload.new_password) < 12 or payload.new_password == payload.current_password:
        raise HTTPException(400, 'Contraseña nueva inválida')
    # Reverify current password before changing. Auth endpoint requires the current session JWT.
    with httpx.Client(timeout=25) as client:
        user = client.get(URL + '/auth/v1/user', headers=api_headers(token)).json()
        verify = client.post(URL + '/auth/v1/token', params={'grant_type': 'password'},
                             headers={'apikey': KEY, 'Content-Type': 'application/json'},
                             json={'email': ADMIN_EMAIL, 'password': payload.current_password})
        if verify.status_code != 200 or verify.json().get('user', {}).get('id') != actor:
            raise HTTPException(403, 'Contraseña actual incorrecta')
        changed = client.put(URL + '/auth/v1/user', headers=api_headers(token), json={'password': payload.new_password})
        if changed.status_code >= 400:
            raise HTTPException(400, 'Supabase Auth rechazó la nueva contraseña')
    # Logout current session; other sessions must be invalidated separately in Auth settings.
    resp = Response(content=json.dumps({'ok': True, 'message': 'Contraseña cambiada; inicia sesión nuevamente'}), media_type='application/json')
    resp.delete_cookie(COOKIE, path='/')
    return resp


@app.get('/api/admin/audit')
def general_audit(request: Request, limit: int = 150):
    token, _ = admin(request)
    rows = select('unit_audit', token, order='created_at.desc', limit=max(1, min(limit, 300)))
    ids = {r['unit_id'] for r in rows if r.get('unit_id')}
    codes = {r['id']: r['code'] for r in select('units', token, cols='id,code') if r['id'] in ids}
    return [{'id': r['id'], 'unit_id': r.get('unit_id'), 'unit_code': codes.get(r.get('unit_id')),
             'actor': r.get('legacy_actor') or 'Administrador', 'action': r['action'],
             'detail': r.get('legacy_detail') or (r.get('detail') or {}).get('text', '') if isinstance(r.get('detail'), dict) else str(r.get('detail') or ''),
             'created_at': r['created_at']} for r in rows]


@app.get('/api/admin/backup')
def backup(request: Request):
    token, _ = admin(request)
    tables = ('unit_types', 'unit_template_items', 'responsibles', 'units', 'unit_reviews', 'unit_photos', 'unit_audit')
    result = io.BytesIO()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    with zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as z:
        manifest = {'format': 'unidad360-cloud-backup-v1', 'created_at': now(), 'tables': {}, 'files': {}}
        for name in tables:
            rows = select_all(name, token)
            raw = json.dumps(rows, ensure_ascii=False, indent=2).encode('utf-8')
            z.writestr('tables/' + name + '.json', raw)
            manifest['tables'][name] = {'rows': len(rows), 'sha256': hashlib.sha256(raw).hexdigest()}
        paths = {r['storage_path'] for r in select_all('unit_photos', token)}
        paths.update(r.get('qr_storage_path') for r in select_all('responsibles', token) if r.get('qr_storage_path'))
        for path in sorted(paths):
            raw = storage_download(token, path)
            z.writestr('storage/' + path, raw)
            manifest['files'][path] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        z.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    return Response(result.getvalue(), media_type='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="UNIDAD360_cloud_{stamp}.zip"',
                             'Cache-Control': 'private, no-store'})

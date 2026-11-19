"""Pruebas del endpoint de eliminación sin conexiones reales a Supabase."""
from pathlib import Path
import importlib.util
import uuid
from fastapi import HTTPException


def get_module():
    base=Path(__file__).resolve().parent
    spec=importlib.util.spec_from_file_location('unidad360_delete_test',base/'cloud_app.py')
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_delete_type_checks_admin_and_blocks_used(monkeypatch):
    mod=get_module()
    called=[]
    monkeypatch.setattr(mod,'admin',lambda request,mutate=False:(called.append(('admin',mutate)) or ('token','actor')))
    monkeypatch.setattr(mod,'single',lambda *a:{'code':'MOD-1'})
    monkeypatch.setattr(mod,'select',lambda *a,**k:[{'id':'some-unit'}])
    monkeypatch.setattr(mod,'remote',lambda *a,**k:called.append(('remote',a)))
    try:
        mod.delete_type(uuid.uuid4(),None)
        assert False,'Debe impedir borrar plantilla utilizada'
    except HTTPException as e:
        assert e.status_code==409
    assert ('admin',True) in called
    assert not any(x[0]=='remote' for x in called)


def test_delete_type_unused(monkeypatch):
    mod=get_module()
    calls=[]
    monkeypatch.setattr(mod,'admin',lambda request,mutate=False:('token','actor'))
    monkeypatch.setattr(mod,'single',lambda *a:{'code':'MOD-2'})
    monkeypatch.setattr(mod,'select',lambda *a,**kw:[])
    monkeypatch.setattr(mod,'remote',lambda *a,**kw:calls.append((a,kw)) or [{'id':'ok'}])
    monkeypatch.setattr(mod,'audit',lambda *a,**kw:calls.append(('audit',a)))
    r=mod.delete_type(uuid.uuid4(),None)
    assert r['ok'] and r['code']=='MOD-2'
    assert calls[0][0][0]=='DELETE'
    assert any(x[0]=='audit' for x in calls if isinstance(x,tuple) and len(x)>0)


def test_ui_has_confirmation_and_button():
    js=(Path(__file__).resolve().parent/'cloud_static'/'app.js').read_text(encoding='utf-8')
    assert 'Eliminar plantilla</button>' in js
    assert 'async function deleteType(id)' in js
    assert 'confirm(`¿Eliminar definitivamente' in js

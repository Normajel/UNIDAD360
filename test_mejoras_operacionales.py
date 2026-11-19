import ast
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

from aplicar_mejoras_operacionales import patch_backend, patch_css, patch_js


def load_period_function():
    path = Path(__file__).with_name('cloud_app.py')
    src = path.read_text(encoding='utf-8')
    tree = ast.parse(src if 'UNIDAD360_OPERACIONES_V4' in src else patch_backend(src))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'period_performance')
    ns = {'datetime':datetime,'timezone':timezone,'HTTPException':HTTPException}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), '<test>', 'exec'),ns)
    return ns['period_performance']


def record(id, created, received=None, started=None, typ='t1'):
    return {'id':id,'code':id,'type_id':typ,'type_code':'T1','nv':'','detail':'stock',
            'created_at':created,'received_at':received,'started_at':started}


def test_cuenta_recepciones_de_periodos_anteriores():
    f=load_period_function()
    rows=[record('A','2026-10-01T01:00:00Z','2026-11-10T02:00:00Z'),
          record('B','2026-11-09T01:00:00Z',None,'2026-11-10T01:00:00Z'),
          record('C','2026-11-12T01:00:00Z',None)]
    p=f(rows,'2026-11-09','2026-11-15')
    assert p['entered']==2
    assert p['received_in_period']==1
    assert p['pending_at_cutoff']==2
    assert p['in_progress_at_cutoff']==1
    assert p['not_started_at_cutoff']==1


def test_estado_historico_no_confunde_recepcion_futura():
    f=load_period_function()
    p=f([record('X','2026-11-01T01:00:00Z','2026-11-20T01:00:00Z','2026-11-03T01:00:00Z')],
        '2026-11-01','2026-11-07')
    assert p['pending_at_cutoff']==1
    assert p['received_in_period']==0
    assert p['units_at_cutoff'][0]['status_at_cutoff']=='pendiente'


def test_rango_invalido_rechazado():
    f=load_period_function()
    with pytest.raises(HTTPException) as ex:
        f([], '2026-11-16','2026-11-09')
    assert ex.value.status_code == 400


def test_css_no_duplicacion():
    assert 'UNIDAD360_OPERACIONES_V4' in patch_css('body{margin:0}')
    with pytest.raises(RuntimeError):patch_css(patch_css('body{margin:0}'))


def test_backend_no_duplicacion():
    s=Path(__file__).with_name('cloud_app.py').read_text(encoding='utf-8')
    if 'UNIDAD360_OPERACIONES_V4' not in s: s = patch_backend(s)
    with pytest.raises(RuntimeError):patch_backend(s)

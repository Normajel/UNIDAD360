"""Pruebas locales sin red para la optimización del panel."""
import cloud_app as cloud
from fastapi.testclient import TestClient


def test_all_units_batch_sin_n_mas_uno(monkeypatch):
    units = [{'id': f'u{i}', 'unit_type_id': 't1'} for i in range(120)]
    calls = []

    def fake_select_all(table, token, **kwargs):
        calls.append(('all', table))
        return {'units': units, 'unit_reviews': [{'unit_id': 'u0', 'position': 0}], 'unit_photos': []}[table]

    def fake_select(table, token, **kwargs):
        calls.append(('one', table))
        return {'unit_types': [{'id': 't1'}], 'responsibles': []}[table]

    def fake_unit_record(token, unit, *, batch=None):
        assert batch is not None
        assert batch['types']['t1']['id'] == 't1'
        if unit['id'] == 'u0':
            assert len(batch['reviews']['u0']) == 1
        return unit

    monkeypatch.setattr(cloud, 'select_all', fake_select_all)
    monkeypatch.setattr(cloud, 'select', fake_select)
    monkeypatch.setattr(cloud, 'unit_record', fake_unit_record)
    assert len(cloud.all_units('token-de-prueba')) == 120
    assert calls == [
        ('all', 'units'), ('one', 'unit_types'), ('one', 'responsibles'),
        ('all', 'unit_reviews'), ('all', 'unit_photos'),
    ]


def test_lista_vacia_no_consulta_tablas_relacionadas(monkeypatch):
    calls = []
    def fake_all(table, token, **kwargs):
        calls.append(table)
        return []
    monkeypatch.setattr(cloud, 'select_all', fake_all)
    assert cloud.all_units('token') == []
    assert calls == ['units']


def test_bootstrap_usa_una_sola_autenticacion(monkeypatch):
    checks = []
    def fake_admin(request):
        checks.append('admin')
        return ('token-de-prueba', 'uid')
    monkeypatch.setattr(cloud, 'admin', fake_admin)
    monkeypatch.setattr(cloud, 'select', lambda table, token, **kwargs: [])
    monkeypatch.setattr(cloud, 'all_units', lambda token: [])
    response = TestClient(cloud.app).get('/api/bootstrap')
    assert response.status_code == 200
    assert response.json() == {'types': [], 'people': [], 'units': []}
    assert checks == ['admin']

import os,tempfile,unittest,importlib,sys
from pathlib import Path
from fastapi.testclient import TestClient

class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        os.environ['UNIDADES_DATA_DIR']=cls.tmp.name
        os.environ['UNIDADES_ADMIN_PASSWORD']='Secure-for-tests-2026!'
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        import app
        cls.mod=app
        app.init_db()
        cls.client=TestClient(app.app)
        r=cls.client.post('/api/login',json={'username':'admin','password':'Secure-for-tests-2026!'})
        assert r.status_code==200,r.text
        cls.headers={'X-CSRF-Token':r.json()['csrf']}
    @classmethod
    def tearDownClass(cls):cls.client.close();cls.tmp.cleanup()
    def test_a_complete_workflow_and_pdf(self):
        c=self.client;h=self.headers
        types=c.get('/api/types').json();self.assertGreater(len(types),0)
        tid=types[0]['id']
        u=c.post('/api/units',json={'code':'TEST-101','detail':'stock','type_id':tid,'nv':'NV-303'},headers=h)
        self.assertEqual(u.status_code,200,u.text)
        d=u.json();uid=d['id'];self.assertEqual(d['status'],'no_iniciada');self.assertEqual(d['nv'],'NV-303')
        # One applicable check and all the rest N/A
        for i,rev in enumerate(d['reviews']):
            r=c.patch(f"/api/units/{uid}/reviews/{rev['id']}",json={'state':'vb' if i==0 else 'na'},headers=h)
            self.assertEqual(r.status_code,200,r.text)
        d=c.get(f'/api/units/{uid}').json();self.assertEqual(d['progress'],100);self.assertEqual(d['status'],'pendiente')
        p1=c.post('/api/people',json={'name':'Trabajador prueba','role':'trabajador','qr_value':'worker-test'},headers=h).json()['id']
        p2=c.post('/api/people',json={'name':'Supervisor prueba','role':'supervisor','qr_value':'super-test'},headers=h).json()['id']
        for role,pid in [('trabajador',p1),('supervisor',p2)]:
            self.assertEqual(c.post(f'/api/units/{uid}/responsible/{role}',json={'person_id':pid},headers=h).status_code,200)
        d=c.get(f'/api/units/{uid}').json();self.assertTrue(d['ready_to_receive'])
        r=c.post(f'/api/units/{uid}/receive',json={},headers=h);self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['status'],'finalizada')
        self.assertEqual(c.patch(f'/api/units/{uid}',json={'observations':'edit'},headers=h).status_code,409)
        pdf=c.get(f'/api/units/{uid}/pdf');self.assertEqual(pdf.status_code,200,pdf.text[:100] if pdf.status_code!=200 else '')
        self.assertTrue(pdf.content.startswith(b'%PDF-'))
    def test_prevent_early_receipt(self):
        t=self.client.get('/api/types').json()[0]['id']
        d=self.client.post('/api/units',json={'code':'TEST-102','detail':'arriendo','type_id':t},headers=self.headers).json()
        r=self.client.post(f"/api/units/{d['id']}/receive",headers=self.headers)
        self.assertEqual(r.status_code,409)
    def test_templates_change_only_new_units(self):
        t=self.client.post('/api/types',json={'code':'TESTTYPE','category':'baños'},headers=self.headers).json()['id']
        before=self.client.post('/api/units',json={'code':'TEST-103','detail':'stock','type_id':t},headers=self.headers).json()
        r=self.client.put(f'/api/types/{t}/template',json={'items':[{'title':'Piso','applies':True},{'title':'Luminaria','applies':False}]},headers=self.headers)
        self.assertEqual(r.status_code,200)
        after=self.client.post('/api/units',json={'code':'TEST-104','detail':'stock','type_id':t},headers=self.headers).json()
        self.assertEqual(len(before['reviews']),23)
        self.assertEqual(len(after['reviews']),2)
        self.assertEqual(after['reviews'][1]['state'],'na')
if __name__=='__main__':unittest.main()

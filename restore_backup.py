"""Restauración fuera de línea. Detener Uvicorn antes de ejecutarlo.
Uso: python restore_backup.py ruta/al/respaldo.zip --confirmar
Crea una copia de la carpeta data existente antes de restaurar.
"""
import argparse,hashlib,json,os,shutil,sqlite3,sys,tempfile,zipfile
from pathlib import Path
from datetime import datetime,timezone

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('UNIDADES_DATA_DIR',str(ROOT/'data')))

def restore(path:Path):
    if not path.is_file():raise ValueError('No existe el ZIP indicado')
    with zipfile.ZipFile(path) as z:
        manifest=json.loads(z.read('manifest.json'))
        if manifest.get('format')!='unidad360-backup-v1':raise ValueError('Formato de respaldo no reconocido')
        files=manifest.get('files')
        if not isinstance(files,dict) or 'units.sqlite3' not in files:raise ValueError('Respaldo incompleto')
        # No extraer rutas arbitrarias ni archivos adicionales. Comprobar integridad de todos.
        with tempfile.TemporaryDirectory(dir=DATA.parent if DATA.parent.exists() else ROOT) as tmp:
            staged=Path(tmp)/'restored';staged.mkdir()
            for name,meta in files.items():
                pp=Path(name)
                if pp.is_absolute() or '..' in pp.parts or len(pp.parts)>2 or (len(pp.parts)==2 and pp.parts[0] not in ('photos','qr')) or (len(pp.parts)==1 and name!='units.sqlite3'):
                    raise ValueError('Ruta insegura en el respaldo')
                if name not in z.namelist():raise ValueError('Archivo faltante: '+name)
                raw=z.read(name)
                if hashlib.sha256(raw).hexdigest()!=meta['sha256'] or len(raw)!=meta['size']:
                    raise ValueError('Integridad incorrecta: '+name)
                dest=staged.joinpath(*pp.parts);dest.parent.mkdir(exist_ok=True);dest.write_bytes(raw)
            con=sqlite3.connect(f'file:{staged / "units.sqlite3"}?mode=ro',uri=True)
            try:
                result=con.execute('PRAGMA integrity_check').fetchone()[0]
                if result!='ok':raise ValueError('Base de datos dañada: '+str(result))
                for table in ('users','units','people','reviews','photos','audit'):
                    if not con.execute('SELECT 1 FROM sqlite_master WHERE type="table" AND name=?',(table,)).fetchone():
                        raise ValueError('Falta la tabla '+table)
            finally:con.close()
            for folder in ('photos','qr'):(staged/folder).mkdir(exist_ok=True)
            # Se requiere servidor detenido; comprobación cooperativa de bloqueo SQLITE.
            if DATA.exists() and (DATA/'units.sqlite3').exists():
                check=sqlite3.connect(DATA/'units.sqlite3',timeout=0.1)
                try:
                    check.execute('BEGIN EXCLUSIVE')
                    check.rollback()
                except sqlite3.OperationalError as e:raise RuntimeError('Detén el servidor antes de restaurar') from e
                finally:check.close()
            suffix=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            old=DATA.parent/(DATA.name+'_antes_restaurar_'+suffix)
            if old.exists():raise ValueError('Ya existe carpeta de respaldo previo: '+str(old))
            if DATA.exists():DATA.rename(old)
            try:shutil.move(str(staged),str(DATA))
            except BaseException:
                if old.exists() and not DATA.exists():old.rename(DATA)
                raise
            return old if old.exists() else None

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Restaurar respaldo Unidad360 fuera de línea')
    parser.add_argument('zip',type=Path)
    parser.add_argument('--confirmar',action='store_true',help='Confirmo haber detenido el servidor y deseo reemplazar los datos actuales')
    args=parser.parse_args()
    if not args.confirmar:parser.error('Se necesita --confirmar. Detén Uvicorn y guarda una copia adicional antes de continuar.')
    try:
        previous=restore(args.zip)
        print('Restauración completa. Datos anteriores:',previous or 'No existían')
    except Exception as exc:
        print('No se restauró:',exc,file=sys.stderr);sys.exit(1)

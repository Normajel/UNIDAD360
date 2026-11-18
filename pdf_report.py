"""Professional A4 PDF for unit review, delivery and reception. No database access."""
import io
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, Image, KeepTogether)

NAVY = colors.HexColor('#17304E')
BLUE = colors.HexColor('#2563EB')
GREY = colors.HexColor('#64748B')
LIGHT = colors.HexColor('#F1F5F9')
BORDER = colors.HexColor('#DCE4EE')
GREEN = colors.HexColor('#15803D')
ORANGE = colors.HexColor('#B45309')

def safe(v):
    return escape(str(v if v is not None and v != '' else '—'))

def date_label(value):
    if not value:
        return '—'
    try:
        dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M') + (' UTC' if dt.tzinfo else '')
    except (ValueError,AttributeError):
        return str(value)

def image_fit(path, w, h):
    with PILImage.open(path) as im:
        width,height=im.size
    factor=min(w/width,h/height)
    return Image(str(path),width=width*factor,height=height*factor)

def build_pdf(data, qr_dir, photos_dir, issued_at):
    """Creates a standalone PDF. 6 photos maximum per annex page."""
    qr_dir=Path(qr_dir); photos_dir=Path(photos_dir)
    result=io.BytesIO()
    doc=SimpleDocTemplate(result,pagesize=A4,leftMargin=16*mm,rightMargin=16*mm,
                          topMargin=19*mm,bottomMargin=16*mm,
                          title=f"Informe unidad {data['code']}",author='Control de Entrega de Unidades')
    style=getSampleStyleSheet()
    style.add(ParagraphStyle(name='ReportTitle',fontName='Helvetica-Bold',fontSize=16,leading=19,textColor=NAVY,spaceAfter=7))
    style.add(ParagraphStyle(name='SectionX',fontName='Helvetica-Bold',fontSize=10,leading=13,textColor=NAVY,spaceBefore=12,spaceAfter=6))
    style.add(ParagraphStyle(name='BodyX',fontName='Helvetica',fontSize=8.2,leading=11.5,textColor=NAVY))
    style.add(ParagraphStyle(name='SmallX',fontName='Helvetica',fontSize=7.2,leading=10,textColor=NAVY))
    style.add(ParagraphStyle(name='TinyX',fontName='Helvetica',fontSize=6.6,leading=9,textColor=NAVY))
    style.add(ParagraphStyle(name='PhotoX',fontName='Helvetica',fontSize=7,leading=9,alignment=TA_CENTER,textColor=NAVY))
    p=lambda value,kind='BodyX':Paragraph(str(value),style[kind])
    flow=[]
    finalized=bool(data.get('received_at'))
    state='RECEPCIÓN FINALIZADA' if finalized else 'INFORME PRELIMINAR · SIN RECEPCIÓN FINAL'
    state_color=GREEN if finalized else ORANGE
    flow.append(p('INFORME DE REVISIÓN Y ENTREGA','ReportTitle'))
    state_tbl=Table([[p(safe(state),'SmallX'),p('Emisión: '+safe(date_label(issued_at)),'SmallX')]],colWidths=[104*mm,74*mm])
    state_tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LIGHT),('BOX',(0,0),(-1,-1),0.5,BORDER),('TEXTCOLOR',(0,0),(0,0),state_color),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    flow.append(state_tbl)
    flow.append(p('IDENTIFICACIÓN DE LA UNIDAD','SectionX'))
    pairs=[('Código / número',data.get('code')),('Tipo de unidad',data.get('type_code')),
           ('Detalle',str(data.get('detail','')).upper()),('Nota de venta',data.get('nv') or 'No registrada'),
           ('Fecha de creación',date_label(data.get('created_at'))),('Última modificación',date_label(data.get('updated_at'))),
           ('Fecha de recepción',date_label(data.get('received_at')) if finalized else 'Pendiente de recepción')]
    table=Table([[p('<b>'+safe(k)+'</b>','SmallX'),p(safe(v),'SmallX')] for k,v in pairs],colWidths=[49*mm,129*mm],hAlign='LEFT')
    table.setStyle(TableStyle([('ROWBACKGROUNDS',(0,0),(-1,-1),[colors.white,LIGHT]),('LINEBELOW',(0,0),(-1,-1),.35,BORDER),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
    flow.append(table)
    reviews=data.get('reviews',[])
    vb=sum(x['state']=='vb' for x in reviews)
    na=sum(x['state']=='na' for x in reviews)
    pending=sum(x['state']=='pendiente' for x in reviews)
    applicable=vb+pending
    progress=round(100*vb/applicable) if applicable else 0
    flow.append(p('RESULTADO DE LA REVISIÓN','SectionX'))
    total=Table([[p('<b>APROBADOS</b>','TinyX'),p('<b>NO APLICA</b>','TinyX'),p('<b>PENDIENTES</b>','TinyX'),p('<b>AVANCE</b>','TinyX')],
                 [p(f'<b>{vb}</b>','BodyX'),p(f'<b>{na}</b>','BodyX'),p(f'<b>{pending}</b>','BodyX'),p(f'<b>{progress}%</b>','BodyX')]],colWidths=[44.5*mm]*4)
    total.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),LIGHT),('BOX',(0,0),(-1,-1),.6,BORDER),('INNERGRID',(0,0),(-1,-1),.4,BORDER),('ALIGN',(0,0),(-1,-1),'CENTER'),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
    flow.append(total)
    flow.append(p('LISTA DE VERIFICACIÓN','SectionX'))
    rows=[[p('<b>CONTROL</b>','SmallX'),p('<b>V°B°</b>','SmallX'),p('<b>N/A</b>','SmallX'),p('<b>PEND.</b>','SmallX')]]
    for r in reviews:
        rows.append([p(safe(r.get('title')),'SmallX'), *[p('X' if r.get('state')==s else '','SmallX') for s in ('vb','na','pendiente')]])
    ctbl=Table(rows,colWidths=[133*mm,15*mm,15*mm,15*mm],repeatRows=1,hAlign='LEFT')
    ctbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),NAVY),('TEXTCOLOR',(0,0),(-1,0),colors.white),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,LIGHT]),('LINEBELOW',(0,0),(-1,-1),.3,BORDER),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('ALIGN',(1,0),(-1,-1),'CENTER'),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
    # Column headers use contrasting white text explicitly via their own styling.
    for c,label in enumerate(('CONTROL','V°B°','N/A','PEND.')):
        ctbl._cellvalues[0][c]=Paragraph(label,ParagraphStyle(name=f'Header{c}',fontName='Helvetica-Bold',fontSize=7.2,leading=10,textColor=colors.white))
    flow.append(ctbl)
    flow.append(p('OBSERVACIONES','SectionX'))
    flow.append(p(safe(data.get('observations') or 'Sin observaciones').replace('\n','<br/>')))
    flow.append(p('RESPONSABLES DE ENTREGA Y RECEPCIÓN','SectionX'))
    cells=[]
    for is_deliverer in (True,False):
        prefix='deliverer' if is_deliverer else 'receiver'
        name=data.get(prefix+'_name')
        role='TRABAJADOR QUE ENTREGA' if is_deliverer else 'JEFE / SUPERVISOR QUE RECIBE'
        content=[p('<b>'+role+'</b>','SmallX'),Spacer(1,4),p('Nombre: '+safe(name),'SmallX'),
                 p('Cargo: '+safe(data.get(prefix+'_position')),'SmallX'),p('RUT: '+safe(data.get(prefix+'_rut')),'SmallX')]
        qr=data.get(prefix+'_qr')
        # qr_filename is generated server-side; prevent paths escaping QR directory.
        if qr and Path(qr).name==qr and (qr_dir/qr).is_file():
            content.append(Spacer(1,5));content.append(image_fit(qr_dir/qr,27*mm,27*mm))
        else:
            content.append(p('QR no disponible','SmallX'))
        if not is_deliverer:
            content.append(p('Recepción: '+safe(date_label(data.get('received_at')) if finalized else 'Pendiente'),'SmallX'))
        cells.append(content)
    people_tbl=Table([cells],colWidths=[89*mm,89*mm])
    people_tbl.setStyle(TableStyle([('BOX',(0,0),(-1,-1),.6,BORDER),('INNERGRID',(0,0),(-1,-1),.6,BORDER),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    flow.append(people_tbl)
    flow.append(Spacer(1,6))
    flow.append(p('El QR identifica un registro interno. No reemplaza una firma ni acredita por sí solo la identidad o autorización de la persona.','TinyX'))
    photos=data.get('photos',[])
    if photos:
        for start in range(0,len(photos),6):
            flow.append(PageBreak())
            heading='ANEXO FOTOGRÁFICO' if start==0 else 'ANEXO FOTOGRÁFICO · CONTINUACIÓN'
            flow.append(p(heading,'SectionX'))
            flow.append(p(f'Unidad {safe(data.get("code"))} · Fotos {start+1} a {min(start+6,len(photos))} de {len(photos)}','SmallX'))
            flow.append(Spacer(1,5))
            chunk=photos[start:start+6]
            rows=[]
            for i in range(0,len(chunk),2):
                photo_cells=[]
                for photo in chunk[i:i+2]:
                    filename=photo.get('filename','')
                    path=photos_dir/filename
                    block=[]
                    if filename and Path(filename).name==filename and path.is_file():
                        try:block.append(image_fit(path,76*mm,56*mm))
                        except (OSError,ValueError):block.append(p('Imagen no disponible','PhotoX'))
                    else:block.append(p('Imagen no disponible','PhotoX'))
                    caption=(photo.get('caption') or 'Sin descripción')[:120]
                    block.append(Spacer(1,3));block.append(p(safe(caption),'PhotoX'))
                    block.append(p('Adjuntada: '+safe(date_label(photo.get('created_at'))),'TinyX'))
                    photo_cells.append(block)
                if len(photo_cells)<2:photo_cells.append('')
                rows.append(photo_cells)
            grid=Table(rows,colWidths=[89*mm,89*mm],rowHeights=[75*mm]*len(rows),hAlign='LEFT')
            grid.setStyle(TableStyle([('BOX',(0,0),(-1,-1),.5,BORDER),('INNERGRID',(0,0),(-1,-1),.5,BORDER),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('ALIGN',(0,0),(-1,-1),'CENTER'),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
            flow.append(grid)
    def header_footer(canvas,document):
        canvas.saveState()
        canvas.setFillColor(NAVY);canvas.rect(0,A4[1]-8*mm,A4[0],8*mm,fill=1,stroke=0)
        canvas.setStrokeColor(BORDER);canvas.line(16*mm,14*mm,A4[0]-16*mm,14*mm)
        canvas.setFont('Helvetica',7);canvas.setFillColor(GREY)
        canvas.drawString(16*mm,9.8*mm,f"Unidad {data.get('code','—')} · {data.get('type_code','—')}")
        canvas.drawRightString(A4[0]-16*mm,9.8*mm,f'Página {document.page}')
        canvas.restoreState()
    doc.build(flow,onFirstPage=header_footer,onLaterPages=header_footer)
    result.seek(0)
    return result

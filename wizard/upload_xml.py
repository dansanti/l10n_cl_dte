# -*- coding: utf-8 -*-
from openerp import models, fields, api, _
from openerp.exceptions import UserError
import logging
import base64
import xmltodict
from lxml import etree
import collections
import dicttoxml

_logger = logging.getLogger(__name__)

try:
    from signxml import xmldsig, methods
except ImportError:
    _logger.info('Cannot import signxml')

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

class UploadXMLWizard(models.TransientModel):
    _name = 'sii.dte.upload_xml.wizard'
    _description = 'SII XML from Provider'

    action = fields.Selection([
            ('create_po','Crear Orden de Pedido y Factura'),
            ('create','Crear Solamente Factura'),
            ('response','Acuse de recibo'),
            ('receipt','Recibo de mercaderías'),
            ('validate','Aprobar comercialmente'),
            ], string="Acción", default="create")

    xml_file = fields.Binary(
        string='XML File', filters='*.xml',
        store=True, help='Upload the XML File in this holder')
    filename = fields.Char('File Name')
    inv = fields.Many2one('account.invoice', invisible=True)

    @api.multi
    def confirm(self):
        context = dict(self._context or {})
        active_id = context.get('active_id', []) or []

        if self.action == 'create':
            self.do_create_inv()
        if self.action == 'create_po':
            self.do_create_po()
        if self.action not in ['create','create_po']:
            self.inv = self.env['account.invoice'].browse(active_id)
            self.inv.sii_xml_request = base64.b64decode(self.xml_file)
            self.inv.filename = self.filename
            if self.action == 'response':
                self.do_receipt_deliver()
            if self.action == 'receipt':
                self.do_receipt()
            if self.action == 'validate':
                self.do_validar_comercial()

    def _read_xml(self):
        if self.xml_file:
            string = base64.b64decode(self.xml_file)
        else:
            string = self.inv.sii_xml_request
        xml = xmltodict.parse(string)
        return xml

    def _check_digest_caratula(self):
        if self.xml_file:
            string = base64.b64decode(self.xml_file).encode('UTF-8')
        elif self.inv and self.inv.sii_xml_request:
            string = self.inv.sii_xml_request.encode('UTF-8')
        else :
            raise UserError('No se ha entregado un string o archivo xml')
        xml = etree.fromstring(string)
        string = etree.tostring(xml[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        our = base64.b64encode(self.inv.digest(mess))
        if our != xml[1][0][2][2].text:
            return 2, 'Envio Rechazado - Error de Firma'
        return 0, ''

    def _check_digest_dte(self, dte):
        if self.xml_file:
            string = base64.b64decode(self.xml_file).encode('UTF-8')
        else:
            string = self.inv.sii_xml_request.encode('utf-8')
        xml = etree.fromstring(string)
        if xml[0][0].tag == "{http://www.sii.cl/SiiDte}Caratula":
            d = xml[0][1]
            i = 0
            while d[i].tag != '{http://www.sii.cl/SiiDte}Documento':
                i +=1
            string = etree.tostring(d[i])#doc
            mess = etree.tostring(etree.fromstring(string), method="c14n").replace(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"','')# el replace es necesario debido a que python lo agrega solo
            our = base64.b64encode(self.inv.digest(mess))
            (d[(i+1)][0][2][2].text)
            if our != d[(i+1)][0][2][2].text:
                return 1, 'DTE No Recibido - Error de Firma'
        else:
            for d in xml[0]:
                if d != xml[0][0] and d[0][0][0][0].text == dte['Encabezado']['IdDoc']['TipoDTE'] and d[0][0][0][1].text == dte['Encabezado']['IdDoc']['Folio']:
                    while d[i].tag != '{http://www.sii.cl/SiiDte}Documento':
                        i +=1
                    string = etree.tostring(d[i])#doc
                    mess = etree.tostring(etree.fromstring(string), method="c14n").replace(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"','')# el replace es necesario debido a que python lo agrega solo
                    our = base64.b64encode(self.inv.digest(mess))
                    if our != d[(i+1)][0][2][2].text:
                        return 1, 'DTE No Recibido - Error de Firma'
        return 0, 'DTE Recibido OK'

    def _validar_caratula(self, cara):
        if not self.env['res.company'].search([('vat','like', cara['RutReceptor'].replace('-',''))]):#se usa like porque sii envía rut sin 0 adelante
            return 3, 'Rut no corresponde a nuestra empresa'
        partner_id = self.env['res.partner'].search([('vat','like', cara['RutEmisor'].replace('-',''))])
        if not partner_id and not self.inv:
            return 2, 'Rut no coincide con los registros'
        try:
            if self.xml_file:
                string = base64.b64decode(self.xml_file).encode('UTF-8')
            elif self.inv and self.inv.sii_xml_request:
                string = self.inv.sii_xml_request.encode('UTF-8')
            else :
                raise UserError('No se ha entregado un string o archivo xml')
            self.inv.xml_validator(string, 'env')
        except:
               return 1, 'Envio Rechazado - Error de Schema'
        #for SubTotDTE in cara['SubTotDTE']:
        #    sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(SubTotDTE['TipoDTE']))])
        #    if not sii_document_class:
        #        return  99, 'Tipo de documento desconocido'
        return 0, ''

    def _validar(self, doc):
        cara, glosa = self._validar_caratula(doc[0][0]['Caratula'])
        if cara != 0:
            return cara
        return 0, ''

    def _validar_dte(self, doc):
        res = collections.OrderedDict()
        res['TipoDTE'] = doc['Encabezado']['IdDoc']['TipoDTE']
        res['Folio'] = doc['Encabezado']['IdDoc']['Folio']
        res['FchEmis'] = doc['Encabezado']['IdDoc']['FchEmis']
        res['RUTEmisor'] = doc['Encabezado']['Emisor']['RUTEmisor']
        res['RUTRecep'] = doc['Encabezado']['Receptor']['RUTRecep']
        res['MntTotal'] = doc['Encabezado']['Totales']['MntTotal']
        partner_id = self.env['res.partner'].search([('vat','like', doc['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(doc['Encabezado']['IdDoc']['TipoDTE']))])
        res['EstadoRecepDTE'] = 0
        res['RecepDTEGlosa'] = 'DTE Recibido OK'
        res['EstadoRecepDTE'], res['RecepDTEGlosa'] = self._check_digest_dte(doc)
        if not sii_document_class:
            res['EstadoRecepDTE'] = 99
            res['RecepDTEGlosa'] = 'Tipo de documento desconocido'
            return res
        docu = self.env['account.invoice'].search(
            [
                ('reference','=', doc['Encabezado']['IdDoc']['Folio']),
                ('partner_id','=',partner_id.id),
                ('sii_document_class_id','=',sii_document_class.id)
            ])
        company_id = self.env['res.company'].search([('vat','like', doc['Encabezado']['Receptor']['RUTRecep'].replace('-',''))])
        if not company_id and (not docu or doc['Encabezado']['Receptor']['RUTRecep'] != self.env['account.invoice'].format_vat(docu.company_id.vat) ) :
            res['EstadoRecepDTE'] = 3
            res['RecepDTEGlosa'] = 'Rut no corresponde a la empresa esperada'
            return res
        return res

    def _validar_dtes(self):
        envio = self._read_xml()
        if 'Documento' in envio['EnvioDTE']['SetDTE']['DTE']:
            res = {'RecepcionDTE' : self._validar_dte(envio['EnvioDTE']['SetDTE']['DTE']['Documento'])}
        else:
            res = []
            for doc in envio['EnvioDTE']['SetDTE']['DTE']:
                res.extend([ {'RecepcionDTE' : self._validar_dte(doc['Documento'])} ])
        return res

    def _caratula_respuesta(self, RutResponde, RutRecibe, IdRespuesta="1", NroDetalles=0):
        caratula = collections.OrderedDict()
        caratula['RutResponde'] = RutResponde
        caratula['RutRecibe'] =  RutRecibe
        caratula['IdRespuesta'] = IdRespuesta
        caratula['NroDetalles'] = NroDetalles
        caratula['NmbContacto'] = self.env.user.partner_id.name
        caratula['FonoContacto'] = self.env.user.partner_id.phone
        caratula['MailContacto'] = self.env.user.partner_id.email
        caratula['TmstFirmaResp'] = self.inv.time_stamp()
        return caratula

    def _receipt(self, IdRespuesta):
        envio = self._read_xml()
        if self.xml_file:
            string = base64.b64decode(self.xml_file).encode('UTF-8')
        elif self.inv:
            string = self.inv.sii_xml_request.encode('utf-8')
        else:
            raise UserError('No hay registro de archivo de envío, por favor seleccione el archivo e envío')
        xml = etree.fromstring(string)
        resp = collections.OrderedDict()
        resp['NmbEnvio'] = self.filename
        resp['FchRecep'] = self.inv.time_stamp()
        resp['CodEnvio'] = self.inv._acortar_str(IdRespuesta, 10)
        resp['EnvioDTEID'] = xml[0].attrib['ID']
        resp['Digest'] = xml[1][0][2][2].text
        EstadoRecepEnv, RecepEnvGlosa = self._validar_caratula(envio['EnvioDTE']['SetDTE']['Caratula'])
        if EstadoRecepEnv == 0:
            EstadoRecepEnv, RecepEnvGlosa = self._check_digest_caratula()
        resp['RutEmisor'] = envio['EnvioDTE']['SetDTE']['Caratula']['RutEmisor']
        resp['RutReceptor'] = envio['EnvioDTE']['SetDTE']['Caratula']['RutReceptor']
        resp['EstadoRecepEnv'] = EstadoRecepEnv
        resp['RecepEnvGlosa'] = RecepEnvGlosa
        NroDte = len(envio['EnvioDTE']['SetDTE']['DTE'])
        if 'Documento' in envio['EnvioDTE']['SetDTE']['DTE']:
            NroDte = 1
        resp['NroDTE'] = NroDte
        resp['item'] = self._validar_dtes()
        return resp

    def _RecepcionEnvio(self, Caratula, resultado):
        resp='''<?xml version="1.0" encoding="ISO-8859-1"?>
<RespuestaDTE version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte RespuestaEnvioDTE_v10.xsd" >
    <Resultado ID="Odoo_resp">
        <Caratula version="1.0">
            {0}
        </Caratula>
            {1}
    </Resultado>
</RespuestaDTE>'''.format(Caratula,resultado)
        return resp

    def do_receipt_deliver(self):
        envio = self._read_xml()
        company_id = self.env['res.company'].search(
            [
                ('vat','like', envio['EnvioDTE']['SetDTE']['Caratula']['RutReceptor'].replace('-',''))
            ],
            limit=1)
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        try:
            signature_d = self.env['account.invoice'].get_digital_signature(company_id)
        except:
            raise UserError(_('''There is no Signer Person with an \
        authorized signature for you in the system. Please make sure that \
        'user_signature_key' module has been installed and enable a digital \
        signature, for you or make the signer to authorize you to use his \
        signature.'''))
        certp = signature_d['cert'].replace(
            BC, '').replace(EC, '').replace('\n', '')
        recep = self._receipt(IdRespuesta)
        NroDetalles = len(envio['EnvioDTE']['SetDTE']['DTE'])
        dicttoxml.set_debug(False)
        resp_dtes = dicttoxml.dicttoxml(recep, root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        RecepcionEnvio = '''<RecepcionEnvio>
                    {0}
                    </RecepcionEnvio>
                    '''.format(resp_dtes)
        RutRecibe = envio['EnvioDTE']['SetDTE']['Caratula']['RutEmisor']
        caratula = dicttoxml.dicttoxml(self._caratula_respuesta(self.env['account.invoice'].format_vat(company_id.vat), RutRecibe, IdRespuesta, NroDetalles),
                                       root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        resp = self._RecepcionEnvio(caratula, RecepcionEnvio )

        respuesta = self.inv.sign_full_xml(
            resp, signature_d['priv_key'], certp,
            'Odoo_resp', 'env_resp')
        if self.inv:
            self.inv.sii_xml_response = respuesta
        return {
            'warning': {
                'title': "XML de Respuesta Envío",
                'message': respuesta,
                }
            }

    def _validar_dte_en_envio(self, doc, IdRespuesta):
        res = collections.OrderedDict()
        res['TipoDTE'] = doc['Encabezado']['IdDoc']['TipoDTE']
        res['Folio'] = doc['Encabezado']['IdDoc']['Folio']
        res['FchEmis'] = doc['Encabezado']['IdDoc']['FchEmis']
        res['RUTEmisor'] = doc['Encabezado']['Emisor']['RUTEmisor']
        res['RUTRecep'] = doc['Encabezado']['Receptor']['RUTRecep']
        res['MntTotal'] = doc['Encabezado']['Totales']['MntTotal']
        res['CodEnvio'] = str(IdRespuesta) + str(doc['Encabezado']['IdDoc']['Folio'])
        partner_id = self.env['res.partner'].search([('vat','like', doc['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(doc['Encabezado']['IdDoc']['TipoDTE']))])
        res['EstadoDTE'] = 0
        res['EstadoDTEGlosa'] = 'DTE Aceptado OK'
        if not sii_document_class:
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
            return res

        if doc['Encabezado']['Receptor']['RUTRecep'] != self.inv.company_id.partner_id.document_number:
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
            return res

        if int(round(self.inv.amount_total)) != int(round(doc['Encabezado']['Totales']['MntTotal'])):
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
        #@TODO hacer más Validaciones, como por ejemplo, valores por línea
        return res

    def _resultado(self, IdRespuesta):
        envio = self._read_xml()
        if 'Documento' in envio['EnvioDTE']['SetDTE']['DTE']:
            return {'ResultadoDTE' : self._validar_dte_en_envio(envio['EnvioDTE']['SetDTE']['DTE']['Documento'],IdRespuesta)}
        else:
            for doc in envio['EnvioDTE']['SetDTE']['DTE']:
                if doc['Documento']['Encabezado']['IdDoc']['Folio'] == self.inv.reference:
                    return {'ResultadoDTE' : self._validar_dte_en_envio(doc['Documento'], IdRespuesta)}
        return False

    def _ResultadoDTE(self, Caratula, resultado):
        resp='''<?xml version="1.0" encoding="ISO-8859-1"?>
<RespuestaDTE version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte RespuestaEnvioDTE_v10.xsd" >
    <Resultado ID="Odoo_resp">
        <Caratula version="1.0">
            {0}
        </Caratula>
            {1}
    </Resultado>
</RespuestaDTE>'''.format(Caratula,resultado)

        return resp

    def do_validar_comercial(self):
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        for inv in self.inv:
            if inv.estado_recep_dte not in ['0']:
                try:
                    signature_d = inv.get_digital_signature(inv.company_id)
                except:
                    raise UserError(_('''There is no Signer Person with an \
                authorized signature for you in the system. Please make sure that \
                'user_signature_key' module has been installed and enable a digital \
                signature, for you or make the signer to authorize you to use his \
                signature.'''))
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                dte = self._resultado(IdRespuesta)
        envio = self._read_xml()
        NroDetalles = len(envio['EnvioDTE']['SetDTE']['DTE'])
        if 'Documento' in envio['EnvioDTE']['SetDTE']['DTE']:
            NroDetalles = 1
        dicttoxml.set_debug(False)
        ResultadoDTE = dicttoxml.dicttoxml(dte, root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        RutRecibe = envio['EnvioDTE']['SetDTE']['Caratula']['RutEmisor']
        caratula = dicttoxml.dicttoxml(self._caratula_respuesta(self.env['account.invoice'].format_vat(inv.company_id.vat), RutRecibe, IdRespuesta, NroDetalles),
                                       root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        resp = self._ResultadoDTE(caratula, ResultadoDTE)
        respuesta = self.inv.sign_full_xml(
            resp, signature_d['priv_key'], certp,
            'Odoo_resp', 'env_resp')
        if self.inv:
            self.inv.sii_message = respuesta
        return {
            'warning': {
                'title': "XML de Respuesta Envío",
                'message': respuesta,
                }
            }

    def _recep(self, inv, RutFirma, key, cert):
        receipt = collections.OrderedDict()
        receipt['TipoDoc'] = inv.sii_document_class_id.sii_code
        receipt['Folio'] = int(inv.reference)
        receipt['FchEmis'] = inv.date_invoice
        receipt['RUTEmisor'] = inv.format_vat(inv.partner_id.vat)
        receipt['RUTRecep'] = inv.format_vat(inv.company_id.vat)
        receipt['MntTotal'] = int(round(inv.amount_total))
        receipt['Recinto'] = inv.company_id.street
        receipt['RutFirma'] = RutFirma
        receipt['Declaracion'] = 'El acuse de recibo que se declara en este acto, de acuerdo a lo dispuesto en la letra b) del Art. 4, y la letra c) del Art. 5 de la Ley 19.983, acredita que la entrega de mercaderias o servicio(s) prestado(s) ha(n) sido recibido(s).'
        receipt['TmstFirmaRecibo'] = inv.time_stamp()
        id = "T"+str(inv.sii_document_class_id.sii_code)+"F"+str(inv.get_folio())
        doc = '''
<Recibo version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte Recibos_v10.xsd" >
    <DocumentoRecibo ID="{0}" >
    {1}
    </DocumentoRecibo>
</Recibo>
        '''.format(id, dicttoxml.dicttoxml(receipt, root=False, attr_type=False))
        return self.inv.sign_full_xml(
            doc, key, cert,
            'Recibo', 'recep')

    def _envio_recep(self,caratula, recep):
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<EnvioRecibos xmlns='http://www.sii.cl/SiiDte' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:schemaLocation='http://www.sii.cl/SiiDte EnvioRecibos_v10.xsd' version="1.0">
    <SetRecibos ID="SetDteRecibidos">
        <Caratula version="1.0">
        {0}
        </Caratula>
        {1}
    </SetRecibos>
</EnvioRecibos>'''.format(caratula, recep)
        return xml

    def _caratula_recep(self, RutResponde, RutRecibe):
        caratula = collections.OrderedDict()
        caratula['RutResponde'] = RutResponde
        caratula['RutRecibe'] = RutRecibe
        caratula['NmbContacto'] = self.env.user.partner_id.name
        caratula['FonoContacto'] = self.env.user.partner_id.phone
        caratula['MailContacto'] = self.env.user.partner_id.email
        caratula['TmstFirmaEnv'] = self.inv.time_stamp()
        return caratula

    @api.multi
    def do_receipt(self):
        receipts = ""
        for inv in self.inv:
            if inv.estado_recep_dte not in ['0']:
                try:
                    signature_d = inv.get_digital_signature(inv.company_id)
                except:
                    raise UserError(_('''There is no Signer Person with an \
                authorized signature for you in the system. Please make sure that \
                'user_signature_key' module has been installed and enable a digital \
                signature, for you or make the signer to authorize you to use his \
                signature.'''))
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                receipts += "\n"+self._recep(inv, signature_d['subject_serial_number'],signature_d['priv_key'], certp)
        envio = self._read_xml()
        RutRecibe = envio['EnvioDTE']['SetDTE']['Caratula']['RutEmisor']
        caratula = dicttoxml.dicttoxml(self._caratula_recep(self.env['account.invoice'].format_vat(inv.company_id.vat), RutRecibe), root=False, attr_type=False)
        envio_dte = self._envio_recep(caratula, receipts)
        envio_dte = self.inv.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            'SetDteRecibidos', 'env_recep')
        if self.inv:
            self.inv.sii_receipt = envio_dte
        return {
            'warning': {
                'title': "XML de Respuesta Envío",
                'message': envio_dte,
                }
            }

    def _create_partner(self, data):
        giro_id = self.env['sii.activity.description'].search([('name','=',data['GiroEmis'])])
        if not giro_id:
            giro_id = self.env['sii.activity.description'].create({
                'name': data['GiroEmis'],
            })
        partner_id = self.env['res.partner'].create({
            'name': data['RznSoc'],
            'activity_description': giro_id.id,
            'vat': 'CL'+data['RUTEmisor'].replace('-',''),
            'document_type_id': self.env.ref('l10n_cl_invoice.dt_RUT').id,
            'responsability_id': self.env.ref('l10n_cl_invoice.res_IVARI').id,
            'document_number': data['RUTEmisor'],
            'street': data['DirOrigen'],
            'city':data['CiudadOrigen'],
            'company_type':'company',
            'supplier': True,
        })
        return partner_id

    def _create_prod(self, data):
        product_id = self.env['product.product'].create({
            'name': data['NmbItem'],
            'lst_price': float(data['PrcItem']),
        })
        if 'CdgItem' in data:
            if 'TpoCodigo' in data['CdgItem']:
                if data['CdgItem']['TpoCodigo'] == 'ean13':
                    product_id.barcode = data['CdgItem']['VlrCodigo']
                else:
                    product_id.default_code = data['CdgItem']['VlrCodigo']
            else:
                for c in data['CdgItem']:
                    if c['TpoCodigo'] == 'ean13':
                        product_id.barcode = c['VlrCodigo']
                    else:
                        product_id.default_code = c['VlrCodigo']
        return product_id

    def _buscar_producto(self, line):
        query = product_id = False
        if 'CdgItem' in line:
            if 'VlrCodigo' in line['CdgItem']:
                if line['CdgItem']['TpoCodigo'] == 'ean13':
                    query = [('barcode','=',line['CdgItem']['VlrCodigo'])]
                else:
                    query = [('default_code','=',line['CdgItem']['VlrCodigo'])]
            else:
                for c in line['CdgItem']:
                    if line['CdgItem']['TpoCodigo'] == 'ean13':
                        query = [('barcode','=',c['VlrCodigo'])]
                    else:
                        query = [('default_code','=',c['VlrCodigo'])]
        if not query:
            query = [('name','=',line['NmbItem'])]
        product_id = self.env['product.product'].search(query)
        if not product_id:
            product_id = self._create_prod(line)
        return product_id

    def _prepare_line(self, line, journal, type):
        product_id = self._buscar_producto(line)

        account_id = journal.default_debit_account_id.id
        if type in ('out_invoice', 'in_refund'):
                account_id = journal.default_credit_account_id.id
        if 'MntExe' in line:
            price_subtotal = price_included = float(line['MntExe'])
        else :
            price_subtotal = float(line['MontoItem'])
        discount = 0
        if 'DescuentoPct' in line:
            discount = line['DescuentoPct']
        return [0,0,{
            'name': line['DescItem'] if 'DescItem' in line else line['NmbItem'],
            'product_id': product_id.id,
            'price_unit': line['PrcItem'],
            'discount': discount,
            'quantity': line['QtyItem'],
            'account_id': account_id,
            'price_subtotal': price_subtotal,
            'invoice_line_tax_ids': [(6, 0, product_id.supplier_taxes_id.ids)],
        }]

    def _prepare_invoice(self, dte, company_id, journal_document_class_id):
        partner_id = self.env['res.partner'].search([('vat','like', dte['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        if not partner_id:
            partner_id = self._create_partner(dte['Encabezado']['Emisor'])
        elif not partner_id.supplier:
            partner_id.supplier = True
        return {
            'origin' : 'XML Envío: ' + self.filename.encode('utf-8'),
            'reference': dte['Encabezado']['IdDoc']['Folio'],
            'date_invoice' :dte['Encabezado']['IdDoc']['FchEmis'],
            'partner_id' : partner_id.id,
            'company_id' : company_id.id,
            'account_id': partner_id.property_account_payable_id.id,
            'journal_id': journal_document_class_id.journal_id.id,
            'turn_issuer': company_id.company_activities_ids[0].id,
            'journal_document_class_id':journal_document_class_id.id,
            'sii_xml_request': base64.b64decode(self.xml_file),
            'sii_send_file_name': self.filename,
        }

    def _get_journal(self, sii_code):
        journal_sii = self.env['account.journal.sii_document_class'].search(
                [('sii_document_class_id.sii_code', '=', sii_code),
                ('journal_id.type','=','purchase'),
                ],
        )[0]
        return journal_sii

    def _create_inv(self, dte, company_id):
        if not self.env['account.invoice'].search(
        [
            ('reference','=',dte['Encabezado']['IdDoc']['Folio']),
            ('type','in',['in_invoice','in_refund']),
            ('sii_document_class_id.sii_code','=',dte['Encabezado']['IdDoc']['TipoDTE']),
            ('partner_id.document_number','=', dte['Encabezado']['Emisor']['RUTEmisor']),
        ]):
            journal_document_class_id = self._get_journal(dte['Encabezado']['IdDoc']['TipoDTE'])
            if not journal_document_class_id:
                raise UserError('No existe Diario para el tipo de documento, por favor añada uno primero')
            data = self._prepare_invoice(dte, company_id, journal_document_class_id)
            data['type'] = 'in_invoice'
            if dte['Encabezado']['IdDoc']['TipoDTE'] in ['54', '61']:
                data['type'] = 'in_refund'
            lines =[(5,)]
            if 'NroLinDet' in dte['Detalle']:
                lines.append(self._prepare_line(dte['Detalle'], journal=journal_document_class_id.journal_id, type=data['type']))
            elif len(dte['Detalle']) > 0:
                for line in dte['Detalle']:
                    lines.append(self._prepare_line(line, journal=journal_document_class_id.journal_id, type=data['type']))
            data['invoice_line_ids'] = lines
            inv = self.env['account.invoice'].create(data)
            monto_xml = float(dte['Encabezado']['Totales']['MntTotal'])
            if inv.amount_total == monto_xml:
                return inv
            #cuadrar en caso de descuadre por 1$
            if (inv.amount_total - 1) == monto_xml or (inv.amount_total + 1) == monto_xml:
                inv.amount_total = monto_xml
                for t in inv.tax_line_ids:
                    if t.tax_id.amount == float(dte['Encabezado']['Totales']['TasaIVA']):
                        t.amount = float(dte['Encabezado']['Totales']['IVA'])
                        t.base = float(dte['Encabezado']['Totales']['MntNeto'])
            else:
                raise UserError('¡El documento está completamente descuadrado!')
            return inv
        return False # ya ha sido creada

    def do_create_inv(self):
        envio = self._read_xml()
        resp = self.do_receipt_deliver()
        if 'Documento' in envio['EnvioDTE']['SetDTE']['DTE']:
            dte = envio['EnvioDTE']['SetDTE']['DTE']
            company_id = self.env['res.company'].search(
                [
                    ('vat','like', dte['Documento']['Encabezado']['Receptor']['RUTRecep'].replace('-','')),
                ],
                limit=1)
            if company_id:
                self.inv = self._create_inv(dte['Documento'], company_id)
                if self.inv:
                    self.inv.sii_xml_response = resp['warning']['message']
        else:
            for dte in envio['EnvioDTE']['SetDTE']['DTE']:
                company_id = self.env['res.company'].search(
                    [
                        ('vat','like', dte['Documento']['Encabezado']['Receptor']['RUTRecep'].replace('-','')),
                    ],
                    limit=1)
                if company_id:
                    self.inv = self._create_inv(dte['Documento'], company_id)
                    if self.inv:
                        self.inv.sii_xml_response = resp['warning']['message']
        if not self.inv:
            raise UserError('El archivo XML no contiene documentos para alguna empresa registrada en Odoo, o ya ha sido procesado anteriormente ')
        return resp

    def _create_po(self, dte):
        partner_id = self.env['res.partner'].search([('vat','like', dte['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        if not partner_id:
            partner_id = self._create_partner(dte['Encabezado']['Emisor'])
        elif not partner_id.supplier:
            partner_id.supplier = True
        company_id = self.env['res.company'].search([('vat','like', dte['Encabezado']['Receptor']['RUTRecep'].replace('-',''))])
        data = {
            'partner_ref' : dte['Encabezado']['IdDoc']['Folio'],
            'date_order' :dte['Encabezado']['IdDoc']['FchEmis'],
            'partner_id' : partner_id.id,
            'company_id' : company_id.id,
        }
        lines =[(5,)]
        for line in dte['Detalle']:
            product_id = self.env['product.product'].search([('name','=',line['NmbItem'])])
            if not product_id:
                product_id = self._create_prod(line)
            lines.append([0,0,{
                'name': line['DescItem'] if 'DescItem' in line else line['NmbItem'],
                'product_id': product_id,
                'product_qty': line['QtyItem'],
            }])
        data['order_lines'] = lines
        po = self.env['purchase.order'].create(data)
        po.button_confirm()
        self.inv = self.env['account.invoice'].search([('purchase_id', '=', po.id)])
        #inv.sii_document_class_id = dte['Encabezado']['IdDoc']['TipoDTE']
        return po

    def do_create_po(self):
        #self.validate()
        envio = self._read_xml()
        for dte in envio['EnvioDTE']['SetDTE']['DTE']:
            if dte['TipoDTE'] in ['34', '33']:
                self._create_po(dte['Documento'])
            elif dte['56','61']: # es una nota
                self._create_inv(dte['Documento'])

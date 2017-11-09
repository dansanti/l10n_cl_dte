# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
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
    _logger.warning('Cannot import signxml')

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

class UploadXMLWizard(models.TransientModel):
    _name = 'sii.dte.upload_xml.wizard'
    _description = 'SII XML from Provider'

    action = fields.Selection(
        [
            ('create_po','Crear Orden de Pedido y Factura'),
            ('create','Crear Solamente Factura'),
        ],
        string="Acción",
        default="create",
    )
    xml_file = fields.Binary(
        string='XML File',
        filters='*.xml',
        store=True,
        help='Upload the XML File in this holder',
    )
    filename = fields.Char(
        string='File Name',
    )
    pre_process = fields.Boolean(
        default=True,
    )
    dte_id = fields.Many2one(
        'mail.message.dte',
        string="DTE",
    )
    document_id = fields.Many2one(
        'mail.message.dte.document',
        string="Documento",
    )
    option = fields.Selection(
        [
            ('upload', 'Solo Subir'),
            ('acept', 'Aceptar'),
            ('reject', 'Rechazar'),
        ],
        string="Opción",
    )

    @api.multi
    def confirm(self, ret=False):
        context = dict(self._context or {})
        active_id = context.get('active_id', []) or []
        created = []
        if not self.dte_id:
            dte_id = self.env['mail.message.dte'].search(
                [
                    ('name', '=', self.filename),
                ]
            )
            if not dte_id:
                dte = {
                    'name': self.filename,
                }
                dte_id = self.env['mail.message.dte'].create(dte)
            self.dte_id = dte_id
        if self.pre_process:
            created = self.do_create_pre()
            xml_id = 'l10n_cl_dte.action_dte_process'
        elif self.option == 'reject':
            self.do_reject()
            return
        elif self.action == 'create':
            created = self.do_create_inv()
            xml_id = 'account.action_invoice_tree2'
        if self.action == 'create_po':
            self.do_create_po()
            xml_id = 'purchase.purchase_order_tree'
        if ret:
            return created
        result = self.env.ref('%s' % (xml_id)).read()[0]
        if created:
            domain = eval(result['domain'])
            domain.append(('id', 'in', created))
            result['domain'] = domain
        return result

    def format_rut(self, RUTEmisor=None):
        rut = RUTEmisor.replace('-','')
        if int(rut[:-1]) < 10000000:
            rut = '0' + str(int(rut))
        rut = 'CL' + rut
        return rut

    def _read_xml(self, mode="text"):
        if self.document_id:
            xml = self.document_id.xml
        elif self.xml_file:
            xml = base64.b64decode(self.xml_file).decode('ISO-8859-1').replace('<?xml version="1.0" encoding="ISO-8859-1"?>','').replace('<?xml version="1.0" encoding="ISO-8859-1" ?>','')
        if mode == "etree":
            return etree.fromstring(xml)
        if mode == "parse":
            envio = xmltodict.parse(xml)
            if 'EnvioBOLETA' in envio:
                return envio['EnvioBOLETA']
            elif 'EnvioDTE' in envio:
                return envio['EnvioDTE']
            else:
                return envio
        return xml

    def _check_digest_caratula(self):
        xml = etree.fromstring(self._read_xml(False))
        string = etree.tostring(xml[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        inv_obj = self.env['account.invoice']
        our = base64.b64encode(inv_obj.digest(mess))
        #if our != xml.find("{http://www.w3.org/2000/09/xmldsig#}Signature/{http://www.w3.org/2000/09/xmldsig#}SignedInfo/{http://www.w3.org/2000/09/xmldsig#}Reference/{http://www.w3.org/2000/09/xmldsig#}DigestValue").text:
        #    return 2, 'Envio Rechazado - Error de Firma'
        return 0, 'Envio Ok'

    def _check_digest_dte(self, dte):
        xml = self._read_xml("etree")
        envio = xml.find("{http://www.sii.cl/SiiDte}SetDTE")#"{http://www.w3.org/2000/09/xmldsig#}Signature/{http://www.w3.org/2000/09/xmldsig#}SignedInfo/{http://www.w3.org/2000/09/xmldsig#}Reference/{http://www.w3.org/2000/09/xmldsig#}DigestValue").text
        for e in envio.findall("{http://www.sii.cl/SiiDte}DTE") :
            string = etree.tostring(e.find("{http://www.sii.cl/SiiDte}Documento"))#doc
            mess = etree.tostring(etree.fromstring(string), method="c14n").replace(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"','')# el replace es necesario debido a que python lo agrega solo
            our = base64.b64encode(self.env['account.invoice'].digest(mess))
            their = e.find("{http://www.w3.org/2000/09/xmldsig#}Signature/{http://www.w3.org/2000/09/xmldsig#}SignedInfo/{http://www.w3.org/2000/09/xmldsig#}Reference/{http://www.w3.org/2000/09/xmldsig#}DigestValue").text
            if our != their:
                _logger.warning('DTE No Recibido - Error de Firma: our = %s their=%s' % (our, their))
                #return 1, 'DTE No Recibido - Error de Firma'
        return 0, 'DTE Recibido OK'

    def _validar_caratula(self, cara):
        try:
            self.env['account.invoice'].xml_validator(
                self._read_xml(False),
                'env',
            )
        except:
               return 1, 'Envio Rechazado - Error de Schema'
        self.dte_id.company_id = self.env['res.company'].search([
                ('vat','=', self.format_rut(cara['RutReceptor']))
            ])
        if not self.dte_id.company_id:
            return 3, 'Rut no corresponde a nuestra empresa'
        partner_id = self.env['res.partner'].search(
            [
                ('active','=', True),
                ('parent_id', '=', False),
                ('vat','=', self.format_rut(cara['RutEmisor']))
            ]
        )
#        if not partner_id :
#            return 2, 'Rut no coincide con los registros'
        #for SubTotDTE in cara['SubTotDTE']:
        #    sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(SubTotDTE['TipoDTE']))])
        #    if not sii_document_class:
        #        return  99, 'Tipo de documento desconocido'
        return 0, 'Envío Ok'

    def _validar(self, doc):
        cara, glosa = self._validar_caratula(doc[0][0]['Caratula'])
        return cara, glosa

    def _validar_dte(self, doc):
        res = collections.OrderedDict()
        res['TipoDTE'] = doc['Encabezado']['IdDoc']['TipoDTE']
        res['Folio'] = doc['Encabezado']['IdDoc']['Folio']
        res['FchEmis'] = doc['Encabezado']['IdDoc']['FchEmis']
        res['RUTEmisor'] = doc['Encabezado']['Emisor']['RUTEmisor']
        res['RUTRecep'] = doc['Encabezado']['Receptor']['RUTRecep']
        res['MntTotal'] = doc['Encabezado']['Totales']['MntTotal']
        partner_id = self.env['res.partner'].search([
            ('active','=', True),
            ('parent_id', '=', False),
            ('vat','=', self.format_rut(doc['Encabezado']['Emisor']['RUTEmisor']))
        ])
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
        company_id = self.env['res.company'].search([
                ('vat','=', self.format_rut(doc['Encabezado']['Receptor']['RUTRecep']))
            ])
        if not company_id and (not docu or doc['Encabezado']['Receptor']['RUTRecep'] != self.env['account.invoice'].format_vat(docu.company_id.vat) ) :
            res['EstadoRecepDTE'] = 3
            res['RecepDTEGlosa'] = 'Rut no corresponde a la empresa esperada'
            return res
        return res

    def _validar_dtes(self):
        envio = self._read_xml('parse')
        if 'Documento' in envio['SetDTE']['DTE']:
            res = {'RecepcionDTE' : self._validar_dte(envio['SetDTE']['DTE']['Documento'])}
        else:
            res = []
            for doc in envio['SetDTE']['DTE']:
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
        caratula['TmstFirmaResp'] = self.env['account.invoice'].time_stamp()
        return caratula

    def _receipt(self, IdRespuesta):
        envio = self._read_xml('parse')
        xml = self._read_xml('etree')
        resp = collections.OrderedDict()
        inv_obj = self.env['account.invoice']
        resp['NmbEnvio'] = self.filename
        resp['FchRecep'] = inv_obj.time_stamp()
        resp['CodEnvio'] = inv_obj._acortar_str(IdRespuesta, 10)
        resp['EnvioDTEID'] = xml[0].attrib['ID']
        resp['Digest'] = xml.find("{http://www.w3.org/2000/09/xmldsig#}Signature/{http://www.w3.org/2000/09/xmldsig#}SignedInfo/{http://www.w3.org/2000/09/xmldsig#}Reference/{http://www.w3.org/2000/09/xmldsig#}DigestValue").text
        EstadoRecepEnv, RecepEnvGlosa = self._validar_caratula(envio['SetDTE']['Caratula'])
        if EstadoRecepEnv == 0:
            EstadoRecepEnv, RecepEnvGlosa = self._check_digest_caratula()
        resp['RutEmisor'] = envio['SetDTE']['Caratula']['RutEmisor']
        resp['RutReceptor'] = envio['SetDTE']['Caratula']['RutReceptor']
        resp['EstadoRecepEnv'] = EstadoRecepEnv
        resp['RecepEnvGlosa'] = RecepEnvGlosa
        NroDte = len(envio['SetDTE']['DTE'])
        if 'Documento' in envio['SetDTE']['DTE']:
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

    def _create_attachment(self, xml, name, id=False, model='account.invoice'):
        data = base64.b64encode(xml)
        filename = (name + '.xml').replace(' ','')
        url_path = '/web/binary/download_document?model='+ model +'\
    &field=sii_xml_request&id=%s&filename=%s' % (id, filename)
        att = self.env['ir.attachment'].search(
            [
                ('name','=', filename),
                ('res_id','=', id),
                ('res_model','=',model)
            ],
            limit=1)
        if att:
            return att
        values = dict(
                        name=filename,
                        datas_fname=filename,
                        url=url_path,
                        res_model=model,
                        res_id=id,
                        type='binary',
                        datas=data,
                    )
        att = self.env['ir.attachment'].create(values)
        return att

    def do_receipt_deliver(self):
        envio = self._read_xml('parse')
        if 'Caratula' not in envio['SetDTE']:
           return True
        company_id = self.env['res.company'].search(
            [
                ('vat','=', self.format_rut(envio['SetDTE']['Caratula']['RutReceptor']))
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
        NroDetalles = len(envio['SetDTE']['DTE'])
        dicttoxml.set_debug(False)
        resp_dtes = dicttoxml.dicttoxml(recep, root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        RecepcionEnvio = '''
<RecepcionEnvio>
    {0}
</RecepcionEnvio>
        '''.format(
            resp_dtes,
        )
        RutRecibe = envio['SetDTE']['Caratula']['RutEmisor']
        caratula_recepcion_envio = self._caratula_respuesta(
            self.env['account.invoice'].format_vat(company_id.vat),
            RutRecibe,
            IdRespuesta,
            NroDetalles,
        )
        caratula = dicttoxml.dicttoxml(
            caratula_recepcion_envio,
            root=False,
            attr_type=False,
        ).replace('<item>','\n').replace('</item>','\n')
        resp = self._RecepcionEnvio(caratula, RecepcionEnvio )
        respuesta = self.env['account.invoice'].sign_full_xml(
            resp,
            signature_d['priv_key'],
            certp,
            'Odoo_resp',
            'env_resp')
        if self.dte_id:
            att = self._create_attachment(
                respuesta,
                'recepcion_envio_' + (self.filename or self.dte_id.name) + '_' + str(IdRespuesta),
                self.dte_id.id,
                'mail.message.dte')

            if att:
                values = {
                    'model_id': self.dte_id.id,
                    'email_from': self.dte_id.company_id.dte_email,
                    'email_to': self.dte_id.mail_id.email_from ,
                    'auto_delete': False,
                    'model' : "mail.message.dte",
                    'body':'XML de Respuesta Envío, Estado: %s , Glosa: %s ' % (recep['EstadoRecepEnv'], recep['RecepEnvGlosa'] ),
                    'subject': 'XML de Respuesta Envío' ,
                    'attachment_ids': att.ids,
                }
                send_mail = self.env['mail.mail'].create(values)
                send_mail.send()
            self.dte_id.message_post(
                body='XML de Respuesta Envío, Estado: %s , Glosa: %s ' % (recep['EstadoRecepEnv'], recep['RecepEnvGlosa'] ),
                subject='XML de Respuesta Envío' ,
                attachment_ids= att.ids,
                message_type='comment',
                subtype='mt_comment',
            )

    def _create_partner(self, data):
        if self.pre_process:
            return False
        giro_id = self.env['sii.activity.description'].search([('name','=',data['GiroEmis'])])
        if not giro_id:
            giro_id = self.env['sii.activity.description'].create({
                'name': data['GiroEmis'],
            })
        rut = self.format_rut(data['RUTEmisor'])

        partner_id = self.env['res.partner'].create(
        {
            'name': data['RznSoc'],
            'activity_description': giro_id.id,
            'vat': rut,
            'document_type_id': self.env.ref('l10n_cl_invoice.dt_RUT').id,
            'responsability_id': self.env.ref('l10n_cl_invoice.res_IVARI').id,
            'document_number': data['RUTEmisor'],
            'street': data['DirOrigen'],
            'city':data['CiudadOrigen'] if 'CiudadOrigen' in data else '',
            'company_type':'company',
            'supplier': True,
        })
        return partner_id

    def _default_category(self,):
        md = self.env['ir.model.data']
        res = False
        try:
            res = md.get_object_reference('product', 'product_category_all')[1]
        except ValueError:
            res = False
        return res

    def _buscar_impuesto(self, name="Impuesto", amount=0, sii_code=0, sii_type=False, IndExe=False):
        query = [
            ('amount', '=', amount),
            ('sii_code', '=', sii_code),
            ('type_tax_use', '=', 'purchase'),
        ]
        if IndExe:
            query.append(
                    ('sii_type', '=', False)
            )
        if amount == 0 and sii_code == 0 and not IndExe:
            query.append(
                    ('name', '=', name)
            )
        if sii_type:
            query.extend( [
                ('sii_type', '=', sii_type),
            ])
        imp = self.env['account.tax'].search( query )
        if not imp:
            imp = self.env['account.tax'].sudo().create( {
                'amount': amount,
                'name': name,
                'sii_code': sii_code,
                'sii_type': sii_type,
                'type_tax_use': 'purchase',
            } )
        return ((6,0, imp.ids))

    def _create_prod(self, data):
        product_id = self.env['product.product'].create({
            'sale_ok':False,
            'name': data['NmbItem'],
            'lst_price': float(data['PrcItem'] if 'PrcItem' in data else data['MontoItem']),
            'categ_id': self._default_category(),
        })
        if 'CdgItem' in data:
            if 'TpoCodigo' in data['CdgItem']:
                if data['CdgItem']['TpoCodigo'] == 'ean13':
                    product_id.barcode = data['CdgItem']['VlrCodigo']
                else:
                    product_id.default_code = data['CdgItem']['VlrCodigo']
            else:
                try:
                    Codes = data['CdgItem']['item']
                except:
                    Codes = data['CdgItem']
                for c in Codes:
                    if c['TpoCodigo'] == 'ean13':
                        product_id.barcode = c['VlrCodigo']
                    else:
                        product_id.default_code = c['VlrCodigo']
        return product_id

    def _buscar_producto(self, document_id, line):
        default_code = False
        if document_id:
            code = ' ' + str(line['CdgItem']) if 'CdgItem' in line else ''
            line_id = self.env['mail.message.dte.document.line'].search(
                [
                    '|',
                    ('new_product', '=',  line['NmbItem'] + '' + code),
                    ('product_description', '=', line['DescItem'] if 'DescItem' in line else line['NmbItem']),
                    ('document_id', '=', document_id.id)
                ]
            )
            if line_id:
                if line_id.product_id:
                    return line_id.product_id.id
            else:
                return False
        query = False
        product_id = False
        if 'CdgItem' in line:
            if 'VlrCodigo' in line['CdgItem']:
                if line['CdgItem']['TpoCodigo'] == 'ean13':
                    query = [('barcode','=',line['CdgItem']['VlrCodigo'])]
                else:
                    query = [('default_code','=',line['CdgItem']['VlrCodigo'])]
                default_code = line['CdgItem']['VlrCodigo']
            else:
                try:
                    Codes = line['CdgItem']['item']
                except:
                    Codes = line['CdgItem']
                for c in Codes:
                    if c['TpoCodigo'] == 'ean13':
                        query = [('barcode','=',c['VlrCodigo'])]
                    elif c['TpoCodigo'] == 'INT1':
                        query = [('default_code','=',c['VlrCodigo'])]
                    default_code = c['VlrCodigo']
        if not query:
            query = [('name','=',line['NmbItem'])]
        product_id = self.env['product.product'].search(query)
        query2 = [('name', '=', document_id.partner_id.id)]
        if default_code:
            query2.append(('product_code', '=', default_code))
        else:
            query2.append(('product_name', '=', line['NmbItem']))
        product_supplier = self.env['product.supplierinfo'].search(query2)
        product_id = product_supplier.product_id or self.env['product.product'].search(
            [
                ('product_tmpl_id', '=', product_supplier.product_tmpl_id.id),
            ],
                limit=1)
        if not product_id:
            if not product_supplier and not self.pre_process:
                product_id = self._create_prod(line)
            else:
                code = ' ' + str(line['CdgItem']) if 'CdgItem' in line else ''
                return line['NmbItem'] + '' + code
        if not product_supplier and document_id.partner_id:
            supplier_info = {
                'name': document_id.partner_id.id,
                'product_name' : line['NmbItem'],
                'product_code': default_code,
                'product_tmpl_id': product_id.product_tmpl_id.id,
                'price': float(line['PrcItem'] if 'PrcItem' in line else line['MontoItem']),
            }
            self.env['product.supplierinfo'].create(supplier_info)

        return product_id.id

    def _prepare_line(self, line, document_id, journal, type):
        data = {}
        product_id = self._buscar_producto(document_id, line)
        if isinstance(product_id, int):
            data.update(
                {
                    'product_id': product_id,
                }
            )
        elif not product_id:
            return False

        account_id = journal.default_debit_account_id.id
        if type in ('out_invoice', 'in_refund'):
                account_id = journal.default_credit_account_id.id
        if 'MntExe' in line:
            price_subtotal = float(line['MntExe'])
        else :
            price_subtotal = float(line['MontoItem'])
        discount = 0
        if 'DescuentoPct' in line:
            discount = line['DescuentoPct']
        data.update({
            'name': line['DescItem'] if 'DescItem' in line else line['NmbItem'],
            'price_unit': line['PrcItem'] if 'PrcItem' in line else price_subtotal,
            'discount': discount,
            'quantity': line['QtyItem'] if 'QtyItem' in line else 1,
            'account_id': account_id,
            'price_subtotal': price_subtotal,
        })
        if self.pre_process:
            data.update({
                'new_product': product_id,
                'product_description': line['DescItem'] if 'DescItem' in line else '',
            })
        else:
            product_id = self.env['product.product'].browse(product_id)
            data.update({
                'invoice_line_tax_ids': [(6, 0, product_id.supplier_taxes_id.ids)],
                })

        return [0,0, data]

    def _prepare_ref(self, ref):
        try:
            tpo = self.env['sii.document_class'].search([('sii_code', '=', ref['TpoDocRef'])])
        except:
            tpo = self.env['sii.document_class'].search([('sii_code', '=', 801)])
        if not tpo:
            raise UserError(_('No existe el tipo de documento'))
        folio = ref['FolioRef']
        fecha = ref['FchRef']
        cod_ref = ref['CodRef'] if 'CodRef' in ref else None
        motivo = ref['RazonRef'] if 'RazonRef' in ref else None
        return [0,0,{
            'origen' : folio,
            'sii_referencia_TpoDocRef' : tpo.id,
            'sii_referencia_CodRef' : cod_ref,
            'motivo' : motivo,
            'fecha_documento' : fecha,
        }]

    def _prepare_invoice(self, dte, company_id, journal_document_class_id):
        data = {}
        partner_id = self.env['res.partner'].search(
            [
                ('active','=', True),
                ('parent_id', '=', False),
                ('vat','=', self.format_rut(dte['Encabezado']['Emisor']['RUTEmisor']))
            ]
        )
        if not partner_id:
            partner_id = self._create_partner(dte['Encabezado']['Emisor'])
        elif not partner_id.supplier:
            partner_id.supplier = True
        if partner_id:
            data.update(
            {
                'account_id': partner_id.property_account_payable_id.id,
                'partner_id': partner_id.id,
            })
            partner_id = partner_id.id
        try:
            name = self.filename.decode('ISO-8859-1').encode('UTF-8')
        except:
            name = self.filename.encode('UTF-8')
        xml =base64.b64decode(self.xml_file).decode('ISO-8859-1')
        data.update( {
            'origin' : 'XML Envío: ' + name,
            'date_invoice' :dte['Encabezado']['IdDoc']['FchEmis'],
            'partner_id' : partner_id,
            'company_id' : company_id.id,
            'journal_id': journal_document_class_id.journal_id.id,
            'turn_issuer': company_id.company_activities_ids[0].id,
            'sii_xml_request': xml ,
            'sii_send_file_name': name,
        })

        if partner_id and not self.pre_process:
            data.update({
                'reference': dte['Encabezado']['IdDoc']['Folio'],
                'journal_document_class_id':journal_document_class_id.id,
            })
        else:
            data.update({
                'number': dte['Encabezado']['IdDoc']['Folio'],
                'date' : dte['Encabezado']['IdDoc']['FchEmis'],
                'new_partner': dte['Encabezado']['Emisor']['RUTEmisor'] + ' ' + dte['Encabezado']['Emisor']['RznSoc'],
                'sii_document_class_id': journal_document_class_id.sii_document_class_id.id,
                'amount' : dte['Encabezado']['Totales']['MntTotal'],
            })
        return data

    def _get_journal(self, sii_code, company_id):
        journal_sii = self.env['account.journal.sii_document_class'].search(
            [
                ('sii_document_class_id.sii_code', '=', sii_code),
                ('journal_id.type','=','purchase'),
                ('journal_id.company_id', '=', company_id.id)
            ],
            limit=1,
        )
        return journal_sii

    def _get_data(self, dte, company_id):
        journal_document_class_id = self._get_journal(dte['Encabezado']['IdDoc']['TipoDTE'], company_id)
        if not journal_document_class_id:
            sii_document_class = self.env['sii.document_class'].search([('sii_code', '=', dte['Encabezado']['IdDoc']['TipoDTE'])])
            raise UserError('No existe Diario para el tipo de documento %s, por favor añada uno primero, o ignore el documento' % sii_document_class.name.encode('UTF-8'))
        data = self._prepare_invoice(dte, company_id, journal_document_class_id)
        data['type'] = 'in_invoice'
        if dte['Encabezado']['IdDoc']['TipoDTE'] in ['54', '61']:
            data['type'] = 'in_refund'
        lines = [(5,)]
        document_id = self._dte_exist(dte)
        if 'NroLinDet' in dte['Detalle']:
            new_line = self._prepare_line(dte['Detalle'],document_id=document_id, journal=journal_document_class_id.journal_id, type=data['type'])
            if new_line:
                lines.append(new_line)
        elif len(dte['Detalle']) > 0:
            try:
                Detalles = dte['Detalle']['item']
            except:
                Detalles = dte['Detalle']
            for line in Detalles:
                new_line = self._prepare_line(line, document_id=document_id, journal=journal_document_class_id.journal_id, type=data['type'])
                if new_line:
                    lines.append(new_line)
        product_id = self.env['product.product'].search([
                ('product_tmpl_id', '=', self.env.ref('l10n_cl_dte.product_imp').id),
            ]
        ).id
        if 'ImptoReten' in dte['Encabezado']['Totales']:
            Totales = dte['Encabezado']['Totales']
            imp = self._buscar_impuesto(name="OtrosImps_" + str(Totales['ImptoReten']['TipoImp']), sii_code=Totales['ImptoReten']['TipoImp'])
            lines.append([0,0,{
                'invoice_line_tax_ids': [ imp ],
                'product_id': product_id,
                'name': 'MontoImpuesto %s' % str(Totales['ImptoReten']['TipoImp']),
                'price_unit': Totales['ImptoReten']['MontoImp'],
                'quantity': 1,
                'price_subtotal': Totales['ImptoReten']['MontoImp'],
                'account_id':  journal_document_class_id.journal_id.default_debit_account_id.id
                }]
            )
        #if 'IVATerc' in dte['Encabezado']['Totales']:
        #    imp = self._buscar_impuesto(name="IVATerc" )
        #    lines.append([0,0,{
        #        'invoice_line_tax_ids': [ imp ],
        #        'product_id': product_id,
        #        'name': 'MontoImpuesto IVATerc' ,
        #        'price_unit': dte['Encabezado']['Totales']['IVATerc'],
        #        'quantity': 1,
        #        'price_subtotal': dte['Encabezado']['Totales']['IVATerc'],
        #        'account_id':  journal_document_class_id.journal_id.default_debit_account_id.id
        #        }]
        #    )
        if not self.pre_process and 'Referencia' in dte:
            refs = [(5,)]
            if 'NroLinRef' in dte['Referencia']:
                refs.append(self._prepare_ref(dte['Referencia']))
            else:
                try:
                    Referencias = dte['Referencia']['item']
                except:
                    Referencias = dte['Referencia']
                for ref in Referencias:
                    refs.append(self._prepare_ref(ref))
            data['referencias'] = refs
        data['invoice_line_ids'] = lines
        mnt_neto = int(dte['Encabezado']['Totales']['MntNeto']) if 'MntNeto' in dte['Encabezado']['Totales'] else 0
        mnt_neto += int(dte['Encabezado']['Totales']['MntExe']) if 'MntExe' in dte['Encabezado']['Totales'] else 0
        data['amount_untaxed'] = mnt_neto
        data['amount_total'] = dte['Encabezado']['Totales']['MntTotal']
        if document_id:
            purchase_to_done = False
            if document_id.purchase_to_done:
                purchase_to_done = document_id.purchase_to_done.ids()
            if purchase_to_done:
                data['purchase_to_done'] = purchase_to_done
        return data

    def _inv_exist(self, dte):
        return self.env['account.invoice'].search(
            [
                ('reference','=',dte['Encabezado']['IdDoc']['Folio']),
                ('type', 'in', ['in_invoice','in_refund']),
                ('sii_document_class_id.sii_code','=',dte['Encabezado']['IdDoc']['TipoDTE']),
                ('partner_id.vat','=', self.format_rut(dte['Encabezado']['Emisor']['RUTEmisor'])),
            ])

    def _create_inv(self, documento, company_id):
        inv = self._inv_exist(documento)
        if not inv:
            data = self._get_data(documento, company_id)
            inv = self.env['account.invoice'].create(data)
            monto_xml = float(documento['Encabezado']['Totales']['MntTotal'])
            if inv.amount_total == monto_xml:
                return inv
            inv.amount_total = monto_xml
            for t in inv.tax_line_ids:
                if 'TasaIVA' in documento['Encabezado']['Totales'] and t.tax_id.amount == float(documento['Encabezado']['Totales']['TasaIVA']):
                    t.amount = float(documento['Encabezado']['Totales']['IVA'])
                    t.base = float(documento['Encabezado']['Totales']['MntNeto'])
                else:
                    t.base = documento['Encabezado']['Totales']['MntExe']
        return inv

    def _dte_exist(self, dte):
        return self.env['mail.message.dte.document'].search(
            [
                ('number','=',dte['Encabezado']['IdDoc']['Folio']),
                ('sii_document_class_id.sii_code','=',dte['Encabezado']['IdDoc']['TipoDTE']),
                '|',
                ('partner_id.vat', '=', self.format_rut(dte['Encabezado']['Emisor']['RUTEmisor'])),
                ('new_partner', '=', dte['Encabezado']['Emisor']['RUTEmisor'] + ' ' + dte['Encabezado']['Emisor']['RznSoc']),
            ]
        )

    def _create_pre(self, documento, company_id):
        dte = self._dte_exist(documento)
        if not dte:
            data = self._get_data(documento, company_id)
            data.update({
                'dte_id': self.dte_id.id,
            })
            return self.env['mail.message.dte.document'].create(data)
        _logger.warning(_("El documento ya se encuentra regsitrado" ))
        return dte

    def _get_dtes(self):
        dtes = []
        envio = self._read_xml('parse')
        if 'Documento' in envio['SetDTE']['DTE']:
            dte = envio['SetDTE']['DTE']
            dtes.append(dte)
        else:
            for dte in envio['SetDTE']['DTE']:
                dtes.append(dte)
        return dtes

    def do_create_pre(self):
        created = []
        resp = self.do_receipt_deliver()
        dtes = self._get_dtes()
        for dte in dtes:
            try:
                company_id = self.env['res.company'].search(
                    [
                        ('vat','=', self.format_rut(dte['Documento']['Encabezado']['Receptor']['RUTRecep'])),
                    ],
                    limit=1,
                )
                pre = self._create_pre(
                    dte['Documento'],
                    company_id,
                )
                if pre:
                    inv = self._inv_exist(dte['Documento'])
                    pre.write({
                        'xml': dicttoxml.dicttoxml(
                                {'DTE': dte },
                                root=False,
                                attr_type=False,
                                ),
                        'invoice_id' : inv.id ,
                        }
                    )
                    created.append(pre.id)
            except Exception as e:
                _logger.warning('Error en 1 factura con error:  %s' % str(e))
        return created

    def do_create_inv(self):
        created = []
        dte = self._read_xml('parse')
        try:
            company_id = self.document_id.company_id
            if not company_id:
                company_id = self.env['res.company'].search(
                    [
                        ('vat','=', self.format_rut(dte['DTE']['Documento']['Encabezado']['Receptor']['RUTRecep'])),
                    ],
                    limit=1,
                )
            inv = self._create_inv(
                dte['DTE']['Documento'],
                company_id,
            )
            if self.document_id :
                self.document_id.invoice_id = inv.id
            if inv:
                created.append(inv.id)
            if not inv:
                raise UserError('El archivo XML no contiene documentos para alguna empresa registrada en Odoo, o ya ha sido procesado anteriormente ')
        except Exception as e:
            _logger.warning('Error en 1 factura con error:  %s' % str(e))
        if created and self.option not in [False, 'upload']:
            wiz_acept = self.env['sii.dte.validar.wizard'].create(
                {
                    'invoice_ids': [(6, 0, created)],
                    'action': 'validate',
                    'option': self.option,
                }
            )
            wiz_acept.confirm()
        return created


    def _create_po(self, dte):
        partner_id = self.env['res.partner'].search([
            ('active','=', True),
            ('parent_id', '=', False),
            ('vat','=', self.format_rut(dte['Encabezado']['Emisor']['RUTEmisor'])),
        ])
        if not partner_id:
            partner_id = self._create_partner(dte['Encabezado']['Emisor'])
        elif not partner_id.supplier:
            partner_id.supplier = True
        company_id = self.env['res.company'].search(
            [
                ('vat','=', self.format_rut(dte['Encabezado']['Receptor']['RUTRecep'])),
            ],
        )
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
        inv = self.env['account.invoice'].search([('purchase_id', '=', po.id)])
        #inv.sii_document_class_id = dte['Encabezado']['IdDoc']['TipoDTE']
        return po

    def do_create_po(self):
        #self.validate()
        envio = self._read_xml('parse')
        for dte in envio['SetDTE']['DTE']:
            if dte['TipoDTE'] in ['34', '33']:
                self._create_po(dte['Documento'])
            elif dte['56','61']: # es una nota
                self._create_inv(dte['Documento'])

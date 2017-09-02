# -*- coding: utf-8 -*-
from openerp import models, fields, api, _
from openerp.exceptions import UserError
import logging
import base64
import collections
_logger = logging.getLogger(__name__)

try:
    import dicttoxml
except:
    _logger.warning('No se ha podido cargar dicttoxml')

try:
    import xmltodict
except:
    _logger.warning('No se ha podido cargar xmltodict')

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

class ValidarDTEWizard(models.TransientModel):
    _name = 'sii.dte.validar.wizard'
    _description = 'SII XML from Provider'

    def _get_docs(self):
        context = dict(self._context or {})
        active_ids = context.get('active_ids', []) or []
        return [(6, 0, active_ids)]

    action = fields.Selection(
        [
            ('receipt','Recibo de mercaderías'),
            ('validate','Aprobar comercialmente'),
        ],
        string="Acción",
        default="validate",
    )
    invoice_ids = fields.Many2many(
        'account.invoice',
        string="Facturas",
        default=_get_docs,
    )
    option = fields.Selection(
        [
            ('acept', 'Aceptar'),
            ('reject', 'Rechazar'),
        ],
        string="Opción",
    )

    @api.multi
    def confirm(self):
        #if self.action == 'validate':
        self.do_receipt()
        self.do_validar_comercial()
        #   _logger.info("ee")

    def send_message(self, message="RCT"):
        id = self.document_id.number or self.inv.ref
        sii_document_class = self.document_id.sii_document_class_id or self.inv.sii_document_class_id.sii_code

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
            limit=1,
        )
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

    def _resultado(self, TipoDTE, Folio, FchEmis, RUTEmisor, RUTRecep, MntTotal, IdRespuesta):
        res = collections.OrderedDict()
        res['TipoDTE'] = TipoDTE
        res['Folio'] = Folio
        res['FchEmis'] = FchEmis
        res['RUTEmisor'] = RUTEmisor
        res['RUTRecep'] = RUTRecep
        res['MntTotal'] = MntTotal
        res['CodEnvio'] = str(IdRespuesta)
        res['EstadoDTE'] = 0
        res['EstadoDTEGlosa'] = 'DTE Aceptado OK'
        if self.option == "reject":
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1" #User Reject
        return { 'ResultadoDTE': res }

    def _ResultadoDTE(self, Caratula, resultado):
        resp='''<?xml version="1.0" encoding="ISO-8859-1"?>
<RespuestaDTE version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte RespuestaEnvioDTE_v10.xsd" >
    <Resultado ID="Odoo_resp">
        <Caratula version="1.0">
            {0}
        </Caratula>
            {1}
    </Resultado>
</RespuestaDTE>'''.format(
            Caratula,
            resultado,
        )
        return resp

    def do_reject(self, document_ids):
        dicttoxml.set_debug(False)
        inv_obj = self.env['account.invoice']
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        NroDetalles = 1
        for doc in document_ids:
            try:
                signature_d = inv_obj.get_digital_signature(doc.company_id)
            except:
                raise UserError(_('''There is no Signer Person with an \
            authorized signature for you in the system. Please make sure that \
            'user_signature_key' module has been installed and enable a digital \
            signature, for you or make the signer to authorize you to use his \
            signature.'''))
            certp = signature_d['cert'].replace(
                BC, '').replace(EC, '').replace('\n', '')
            xml = xmltodict.parse(doc.xml)['DTE']['Documento']
            dte = self._resultado(
                TipoDTE=xml['Encabezado']['IdDoc']['TipoDTE'],
                Folio=xml['Encabezado']['IdDoc']['Folio'],
                FchEmis=xml['Encabezado']['IdDoc']['FchEmis'],
                RUTEmisor=xml['Encabezado']['Emisor']['RUTEmisor'],
                RUTRecep=xml['Encabezado']['Receptor']['RUTRecep'],
                MntTotal=xml['Encabezado']['Totales']['MntTotal'],
                IdRespuesta=IdRespuesta,
            )
            ResultadoDTE = dicttoxml.dicttoxml(
                dte,
                root=False,
                attr_type=False,
            ).replace('<item>','\n').replace('</item>','\n')
            RutRecibe = xml['Encabezado']['Emisor']['RUTEmisor']
            caratula_validacion_comercial = self._caratula_respuesta(
                xml['Encabezado']['Receptor']['RUTRecep'],
                RutRecibe,
                IdRespuesta,
                NroDetalles)
            caratula = dicttoxml.dicttoxml(
                caratula_validacion_comercial,
                root=False,
                attr_type=False).replace('<item>','\n').replace('</item>','\n')
            resp = self._ResultadoDTE(
                caratula,
                ResultadoDTE,
            )
            respuesta = inv_obj.sign_full_xml(
                resp,
                signature_d['priv_key'],
                certp,
                'Odoo_resp',
                'env_resp')
            att = self._create_attachment(
                respuesta,
                'rechazo_comercial_' + str(IdRespuesta),
                id=doc.id,
                model="mail.message.dte.document",
            )
            partners = doc.partner_id.ids
            if not doc.partner_id:
                if att:
                    values = {
                        'model_id': doc.id,
                        'email_from': doc.company_id.dte_email,
                        'email_to': doc.dte_id.sudo().mail_id.email_from ,
                        'auto_delete': False,
                        'model' : "mail.message.dte.document",
                        'body':'XML de Respuesta Envío, Estado: %s , Glosa: %s ' % (recep['EstadoRecepEnv'], recep['RecepEnvGlosa'] ),
                        'subject': 'XML de Respuesta Envío' ,
                        'attachment_ids': att.ids,
                    }
                    send_mail = self.env['mail.mail'].create(values)
                    send_mail.send()
            doc.message_post(
                body='XML de Rechazo Comercial, Estado: %s, Glosa: %s' % (dte['ResultadoDTE']['EstadoDTE'], dte['ResultadoDTE']['EstadoDTEGlosa']),
                subject='XML de Validación Comercial',
                partner_ids=partners,
                attachment_ids=[ att.id ],
                message_type='comment',
                subtype='mt_comment',
            )

            inv_obj.set_dte_claim(
                rut_emisor = xml['Encabezado']['Emisor']['RUTEmisor'],
                company_id=doc.company_id,
                sii_document_number=doc.number,
                sii_document_class_id=doc.sii_document_class_id,
                claim='RCD',
            )

    def do_validar_comercial(self):
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        NroDetalles = 1
        dicttoxml.set_debug(False)
        for inv in self.invoice_ids:
            if inv.claim in ['ACD', 'RCD']:
                continue
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
            dte = self._resultado(
                TipoDTE=inv.sii_document_class_id.sii_code,
                Folio=inv.reference,
                FchEmis=inv.date_invoice,
                RUTEmisor=inv.format_vat(inv.partner_id.vat),
                RUTRecep=inv.format_vat(inv.company_id.vat),
                MntTotal=int(round(inv.amount_total, 0)),
                IdRespuesta=IdRespuesta,
            )
            ResultadoDTE = dicttoxml.dicttoxml(
                dte,
                root=False,
                attr_type=False,
            ).replace('<item>','\n').replace('</item>','\n')
            RutRecibe = inv.format_vat(inv.partner_id.vat)
            caratula_validacion_comercial = self._caratula_respuesta(
                inv.format_vat(inv.company_id.vat),
                RutRecibe,
                IdRespuesta,
                NroDetalles,
            )
            caratula = dicttoxml.dicttoxml(
                caratula_validacion_comercial,
                root=False,
                attr_type=False,
            ).replace('<item>','\n').replace('</item>','\n')
            resp = self._ResultadoDTE(
                caratula,
                ResultadoDTE,
            )
            respuesta = inv.sign_full_xml(
                resp,
                signature_d['priv_key'],
                certp,
                'Odoo_resp',
                'env_resp',
            )
            inv.sii_message = respuesta
            att = self._create_attachment(
                respuesta,
                'validacion_comercial_' + str(IdRespuesta),
            )
            inv.message_post(
                body='XML de Validación Comercial, Estado: %s, Glosa: %s' % (dte['ResultadoDTE']['EstadoDTE'], dte['ResultadoDTE']['EstadoDTEGlosa']),
                subject='XML de Validación Comercial',
                partner_ids=[inv.partner_id.id],
                attachment_ids=[ att.id ],
                message_type='comment',
                subtype='mt_comment',
            )
            inv.claim = 'ACD'
            inv.set_dte_claim(
                rut_emisor=inv.format_vat(inv.partner_id.vat),
            )

    def _recep(self, inv, RutFirma):
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
        return receipt

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
        caratula['TmstFirmaEnv'] = self.env['account.invoice'].time_stamp()
        return caratula

    @api.multi
    def do_receipt(self):
        message = ""
        for inv in self.invoice_ids:
            if inv.claim in ['ACD', 'RCD']:
                continue
            try:
                signature_d = inv.get_digital_signature(inv.company_id)
            except:
                raise UserError(_('''There is no Signer Person with an \
            authorized signature for you in the system. Please make sure that \
            'user_signature_key' module has been installed and enable a digital \
            signature, for you or make the signer to authorize you to use his \
            signature.'''))
            certp = signature_d['cert'].replace(
                BC,
                '',
            ).replace(EC, '').replace('\n', '')
            dict_recept = self._recep(
                inv,
                signature_d['subject_serial_number'],
            )
            id = "T" + str(inv.sii_document_class_id.sii_code) + "F" + str(inv.get_folio())
            doc = '''
<Recibo version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte Recibos_v10.xsd" >
    <DocumentoRecibo ID="{0}" >
    {1}
    </DocumentoRecibo>
</Recibo>
            '''.format(
                id,
                dicttoxml.dicttoxml(
                    dict_recept,
                    root=False,
                    attr_type=False,
                ),
            )
            message += '\n ' + str(dict_recept['Folio']) + ' ' + dict_recept['Declaracion']
            receipt = inv.sign_full_xml(
                doc,
                signature_d['priv_key'],
                certp,
                'Recibo',
                'recep')
            RutRecibe = inv.format_vat(inv.partner_id.vat)
            dict_caratula = self._caratula_recep(
                inv.format_vat(inv.company_id.vat),
                RutRecibe,
            )
            caratula = dicttoxml.dicttoxml(
                dict_caratula,
                root=False,
                attr_type=False,
            )
            envio_dte = self._envio_recep(
                caratula,
                receipt,
            )
            envio_dte = inv.sign_full_xml(
                envio_dte,
                signature_d['priv_key'],
                certp,
                'SetDteRecibidos',
                'env_recep',
            )
            att = self._create_attachment(
                envio_dte,
                'recepcion_mercaderias_' + str(inv.sii_send_file_name),
                )
            inv.message_post(
                body='XML de Recepción de Mercaderías\n %s' % (message),
                subject='XML de Recepción de Documento',
                partner_ids=[ inv.partner_id.id ],
                attachment_ids=[ att.id ],
                message_type='comment',
                subtype='mt_comment',
            )
            inv.claim = 'ERM'
            inv.set_dte_claim(
                rut_emisor=inv.format_vat(inv.partner_id.vat),
            )

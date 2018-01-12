# -*- coding: utf-8 -*-

from openerp import fields, models, api, _
import ast
from datetime import datetime
from openerp.tools import DEFAULT_SERVER_DATETIME_FORMAT as DTF
import logging
_logger = logging.getLogger(__name__)

class ColaEnvio(models.Model):
    _name = "sii.cola_envio"

    doc_ids = fields.Char(string="Id Documentos")
    model = fields.Char(string="Model destino")
    user_id = fields.Many2one('res.users')
    tipo_trabajo = fields.Selection([('pasivo', 'pasivo'), ('envio', 'Envío'),('consulta', 'Consulta')], string="Tipo de trabajo")
    active = fields.Boolean(string="Active", default=True)
    n_atencion = fields.Char(string="Número atención")
    date_time = fields.Datetime('Auto Envío al SII')
    send_email = fields.Boolean(
            string="Auto Enviar Email",
            default=False,
        )

    def enviar_email(self, doc):
        att = doc._create_attachment()
        body = 'XML de Intercambio DTE: %s' % (doc.document_number)
        subject = 'XML de Intercambio DTE: %s' % (doc.document_number)
        doc.message_post(
            body=body,
            subject=subject,
            partner_ids=[doc.partner_id.id],
            attachment_ids=att.ids,
            message_type='comment',
            subtype='mt_comment',
        )
        if doc.partner_id.dte_email == doc.partner_id.email:
            return
        values = {
            'email_from': doc.company_id.dte_email,
            'email_to': doc.partner_id.dte_email,
            'auto_delete': False,
            'model' : self.model,
            'body': body,
            'subject': subject,
            'attachment_ids': att.ids,
        }
        send_mail = self.env['mail.mail'].create(values)
        send_mail.send()

    def _procesar_tipo_trabajo(self):
        docs = self.env[self.model].browse(ast.literal_eval(self.doc_ids))
        if self.tipo_trabajo in [ 'pasivo' ]:
            if docs[0].sii_result not in ['', 'NoEnviado']:
                self.unlink()
                return
            if self.date_time and datetime.now() >= datetime.strptime(self.date_time, DTF):
                for d in docs:
                    d.sii_result = 'EnCola'
                try:
                    docs.do_dte_send()
                    if docs[0].sii_send_ident:
                        if self.send_email and docs[0].sii_result in ['Proceso', 'Reparo']:
                            for doc in docs:
                                self.enviar_email(doc)
                        self.tipo_trabajo = 'consulta'
                except Exception as e:
                    for d in docs:
                        d.sii_result = 'NoEnviado'
                    _logger.warning('Error en Envío automático')
                    _logger.warning(str(e))
            return
        if docs[0].sii_send_ident and docs[0].sii_message and docs[0].sii_result in ['Proceso', 'Reparo', 'Rechazado']:
            self.unlink()
            return
        else:
            for doc in docs :
                doc.responsable_envio = self.user_id
            if self.tipo_trabajo == 'envio' or not docs[0].sii_send_ident:
                try:
                    docs.do_dte_send(self.n_atencion)
                    if docs[0].sii_result not in ['', 'NoEnviado']:
                        if self.send_email and docs[0].sii_result in ['Proceso', 'Reparo']:
                            for doc in docs:
                                self.enviar_email(doc)
                        self.tipo_trabajo = 'consulta'
                except Exception as e:
                    _logger.warning("Error en envío Cola")
                    _logger.warning(str(e))
            else:
                try:
                    docs[0].ask_for_dte_status()
                except Exception as e:
                    _logger.warning("Error en Consulta")
                    _logger.warning(str(e))

    @api.model
    def _cron_procesar_cola(self):
        ids = self.search([('active','=',True)])
        if ids:
            for c in ids:
                c._procesar_tipo_trabajo()

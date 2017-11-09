# -*- coding: utf-8 -*-
from odoo import fields, models, api, _
import ast
from datetime import datetime
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT as DTF
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
                        self.tipo_trabajo = 'consulta'
                except Exception as e:
                    for d in docs:
                        d.sii_result = 'NoEnviado'
                    _logger.warning('Error en Envío automático')
                    _logger.warning(str(e))
            return
        if docs[0].sii_send_ident and docs[0].sii_message and docs[0].sii_result in ['Proceso', 'Rechazado']:
            self.unlink()
            return
        else:
            for doc in docs :
                doc.responsable_envio = self.user_id
            if self.tipo_trabajo == 'envio' or not docs[0].sii_send_ident:
                try:
                    docs.do_dte_send(self.n_atencion)
                    if docs[0].sii_result not in ['', 'NoEnviado']:
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

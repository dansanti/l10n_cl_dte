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

    @api.model
    def _cron_procesar_cola(self):
        ids = self.search([('active','=',True)])
        if ids:
            for c in ids:
                docs = self.env[c.model].browse(ast.literal_eval(c.doc_ids))
                if c.tipo_trabajo in [ 'pasivo' ]:
                    if docs[0].sii_result not in ['', 'NoEnviado']:
                        c.unlink()
                        continue
                    if c.date_time and datetime.now() >= datetime.strptime(c.date_time, DTF):
                        for d in docs:
                            d.sii_result = 'EnCola'
                        try:
                            docs.do_dte_send()
                            c.tipo_trabajo = 'consulta'
                        except Exception as e:
                            for d in docs:
                                d.sii_result = 'NoEnviado'
                            _logger.info('Error en Envío automático')
                            _logger.info(str(e))
                    continue
                if docs[0].sii_send_ident and docs[0].sii_message and docs[0].sii_result in ['Proceso','Rechazado']:
                    c.unlink()
                    continue
                else:
                    for doc in docs :
                        doc.responsable_envio = c.user_id
                    if c.tipo_trabajo == 'envio':
                        try:
                            docs.do_dte_send(c.n_atencion)
                            if docs[0].sii_result not in ['', 'NoEnviado']:
                                c.tipo_trabajo = 'consulta'
                        except Exception as e:
                            _logger.info("Error en envío Cola")
                            _logger.info(str(e))
                    else:
                        try:
                            docs[0].ask_for_dte_status()
                        except Exception as e:
                            _logger.info("Error en Consulta")
                            _logger.info(str(e))

# -*- coding: utf-8 -*-
from openerp import models, fields, api, _
from openerp.exceptions import UserError
import logging
import base64
_logger = logging.getLogger(__name__)


class UploadXMLWizard(models.TransientModel):
    _name = 'sii.dte.upload_xml.wizard'
    _description = 'SII XML from Provider'

    action = fields.Selection([
            ('create','Crear/Llenar Factura y dar acuse de recibo a partir de XML'),
            ('response','Acuse de recibo') ,
            ('receipt','Recibo de mercaderías'),
            ('validate','Aprobar comercialmente'),
            ], string="Acción", default="response")

    xml_file = fields.Binary(
        string='XML File', filters='*.xml', required=True,
        store=True, help='Upload the XML File in this holder')
    filename = fields.Char('File Name')

    @api.multi
    def confirm(self):
        context = dict(self._context or {})
        active_id = context.get('active_id', []) or []
        inv = self.env['account.invoice'].browse(active_id)
        inv.sii_xml_request = base64.b64decode(self.xml_file)
        inv.sii_send_file_name = self.filename
        if self.action == 'response':
            inv.do_receipt_deliver()
        if self.action == 'receipt':
            inv.do_receipt()
        if self.action == 'validate':
            inv.do_validar_comercial()

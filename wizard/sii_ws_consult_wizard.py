# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################
from odoo import models, fields, api, _
from odoo.exceptions import Warning


class sii_ws_consult_wizard(models.TransientModel):
    _name = 'sii.ws.consult.wizard'
    _description = 'SII WS Consult Wizard'

    number = fields.Integer(
        'Number',
        required=True,
        )

    @api.multi
    def confirm(self):
        self.ensure_one()
        journal_sii_document_class_id = self._context.get('active_id', False)
        if not journal_sii_document_class_id:
            raise Warning(_(
                'No Journal Document Class as active_id on context'))
        journal_doc_class = self.env[
            'account.journal.sii_document_class'].browse(
            journal_sii_document_class_id)
        return journal_doc_class.get_pysiiws_consult_invoice(self.number)

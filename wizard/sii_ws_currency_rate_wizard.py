# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################
from odoo import models, fields, api, _
from odoo.exceptions import Warning


class sii_ws_currency_rate_wizard(models.TransientModel):
    _name = 'sii.ws.currency_rate.wizard'
    _description = 'SII WS Currency Rate Wizard'

    currency_id = fields.Many2one(
        'res.currency',
        'Currency',
        required=True,
        )

    @api.multi
    def confirm(self):
        self.ensure_one()
        point_of_sale_id = self._context.get('active_id', False)
        if not point_of_sale_id:
            raise Warning(_(
                'No Point Of sale as active_id on context'))
        point_of_sale = self.env[
            'sii.point_of_sale'].browse(point_of_sale_id)
        return point_of_sale.get_pysiiws_currency_rate(self.currency_id)

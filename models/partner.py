from odoo import fields, models, api, _
from odoo.exceptions import UserError
import logging

class dteEmail(models.Model):
    '''
    Email for DTE stuff
    '''
    _inherit = 'res.partner'

    dte_email = fields.Char('DTE Email')

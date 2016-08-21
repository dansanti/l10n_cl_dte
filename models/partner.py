from openerp import fields, models, api, _


class dteEmail(models.Model):
    '''
    Email for DTE stuff
    '''
    _inherit = 'res.partner'

    dte_email = fields.Char('DTE Email')

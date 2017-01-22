# -*- coding: utf-8 -*-

from openerp import fields, models, api, _
import logging
_logger = logging.getLogger(__name__)

class ProcessMails(models.Model):
    _inherit = "mail.message"

    @api.model
    def create(self, vals):
        mail = super(ProcessMails, self).create(vals)
        if mail.message_type in ['email'] and mail.attachment_ids:
            for att in mail.attachment_ids:
                if att.mimetype in ['text/plain'] and att.name.upper.find('.XML'):
                    vals={
                        'xml_file': att.datas,
                        'filename': att.name,
                    }
                    val = self.env['sii.dte.upload_xml.wizard'].create(vals)
                    val.confirm()
        return mail

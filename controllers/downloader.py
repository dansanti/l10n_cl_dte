from openerp import models, http, api
from openerp.http import request
from openerp.addons.web.controllers.main import serialize_exception, content_disposition

class Binary(http.Controller):

    @http.route('/web/binary/download_document', type='http', auth="public")
    @serialize_exception
    def download_document(self, model, field, id, filename=None, **kw):
        """
        :param str filename: field holding the file's name, if any
        :returns: :class:`werkzeug.wrappers.Response`
        """
        Model = request.registry[model]
        cr, uid, context = request.cr, request.uid, request.context
        fields = [field]
        res = Model.read(cr, uid, [int(id)], fields, context)[0]
        # filecontent = base64.b64decode(res.get(field) or '')
        filecontent = res.get(field)
        print(filecontent)
        if not filecontent:
            return request.not_found()
        else:
            if not filename:
                filename = '%s_%s' % (model.replace('.', '_'), id)
            headers = [
                ('Content-Type', 'application/xml'),
                ('Content-Disposition', content_disposition(filename)),
                ('charset', 'utf-8'),
            ]
            return request.make_response(
                    filecontent, headers=headers, cookies=None)

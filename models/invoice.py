# -*- coding: utf-8 -*-


from openerp import fields, models, api, _
from openerp.exceptions import Warning
from openerp.exceptions import UserError
from datetime import datetime, timedelta
import logging
from lxml import etree
from lxml.etree import Element, SubElement
from lxml import objectify
from lxml.etree import XMLSyntaxError
from openerp import SUPERUSER_ID

import xml.dom.minidom
import pytz


import socket
import collections

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

# ejemplo de suds
import traceback as tb
import suds.metrics as metrics

try:
    from suds.client import Client
except:
    pass

try:
    import urllib3
except:
    pass


#urllib3.disable_warnings()
pool = urllib3.PoolManager()
try:
    import textwrap
except:
    pass

_logger = logging.getLogger(__name__)

try:
    import xmltodict
except ImportError:
    _logger.info('Cannot import xmltodict library')

try:
    import dicttoxml
except ImportError:
    _logger.info('Cannot import dicttoxml library')

try:
    from elaphe import barcode
except ImportError:
    _logger.info('Cannot import elaphe library')

try:
    import M2Crypto
except ImportError:
    _logger.info('Cannot import M2Crypto library')

try:
    import base64
except ImportError:
    _logger.info('Cannot import base64 library')

try:
    import hashlib
except ImportError:
    _logger.info('Cannot import hashlib library')

try:
    import cchardet
except ImportError:
    _logger.info('Cannot import cchardet library')

try:
    from SOAPpy import SOAPProxy
except ImportError:
    _logger.info('Cannot import SOOAPpy')

try:
    from signxml import xmldsig, methods
except ImportError:
    _logger.info('Cannot import signxml')

# timbre patrón. Permite parsear y formar el
# ordered-dict patrón corespondiente al documento
timbre  = """<TED version="1.0"><DD><RE>99999999-9</RE><TD>11</TD><F>1</F>\
<FE>2000-01-01</FE><RR>99999999-9</RR><RSR>\
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</RSR><MNT>10000</MNT><IT1>IIIIIII\
</IT1><CAF version="1.0"><DA><RE>99999999-9</RE><RS>YYYYYYYYYYYYYYY</RS>\
<TD>10</TD><RNG><D>1</D><H>1000</H></RNG><FA>2000-01-01</FA><RSAPK><M>\
DJKFFDJKJKDJFKDJFKDJFKDJKDnbUNTAi2IaDdtAndm2p5udoqFiw==</M><E>Aw==</E></RSAPK>\
<IDK>300</IDK></DA><FRMA algoritmo="SHA1withRSA">\
J1u5/1VbPF6ASXkKoMOF0Bb9EYGVzQ1AMawDNOy0xSuAMpkyQe3yoGFthdKVK4JaypQ/F8\
afeqWjiRVMvV4+s4Q==</FRMA></CAF><TSTED>2014-04-24T12:02:20</TSTED></DD>\
<FRMT algoritmo="SHA1withRSA">jiuOQHXXcuwdpj8c510EZrCCw+pfTVGTT7obWm/\
fHlAa7j08Xff95Yb2zg31sJt6lMjSKdOK+PQp25clZuECig==</FRMT></TED>"""
result = xmltodict.parse(timbre)

server_url = {'SIIHOMO':'https://maullin.sii.cl/DTEWS/','SII':'https://palena.sii.cl/DTEWS/'}

BC = '''-----BEGIN CERTIFICATE-----\n'''
EC = '''\n-----END CERTIFICATE-----\n'''

# hardcodeamos este valor por ahora
import os
xsdpath = os.path.dirname(os.path.realpath(__file__)).replace('/models','/static/xsd/')

connection_status = {
    '0': 'Upload OK',
    '1': 'El Sender no tiene permiso para enviar',
    '2': 'Error en tamaño del archivo (muy grande o muy chico)',
    '3': 'Archivo cortado (tamaño <> al parámetro size)',
    '5': 'No está autenticado',
    '6': 'Empresa no autorizada a enviar archivos',
    '7': 'Esquema Invalido',
    '8': 'Firma del Documento',
    '9': 'Sistema Bloqueado',
    'Otro': 'Error Interno.',
}
'''
Extensión del modelo de datos para contener parámetros globales necesarios
 para todas las integraciones de factura electrónica.
 @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
 @version: 2016-06-11
'''
class invoice(models.Model):
    _inherit = "account.invoice"

    def split_cert(self, cert):
        certf, j = '', 0
        for i in range(0, 29):
            certf += cert[76 * i:76 * (i + 1)] + '\n'
        return certf

    '''
    Funcion que permite crear una plantilla para el EnvioDTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_envio(self, RutEmisor, RutReceptor, FchResol, NroResol,
                              TmstFirmaEnv, EnvioDTE,signature_d,SubTotDTE):
        xml = '''<SetDTE ID="SetDoc">
<Caratula version="1.0">
<RutEmisor>{0}</RutEmisor>
<RutEnvia>{1}</RutEnvia>
<RutReceptor>{2}</RutReceptor>
<FchResol>{3}</FchResol>
<NroResol>{4}</NroResol>
<TmstFirmaEnv>{5}</TmstFirmaEnv>
{6}</Caratula>{7}
</SetDTE>
'''.format(RutEmisor, signature_d['subject_serial_number'], RutReceptor,
           FchResol, NroResol, TmstFirmaEnv, SubTotDTE, EnvioDTE)
        return xml

    def time_stamp(self, formato='%Y-%m-%dT%H:%M:%S'):
        tz = pytz.timezone('America/Santiago')
        return datetime.now(tz).strftime(formato)

    '''
    Funcion auxiliar para conversion de codificacion de strings
     proyecto experimentos_dte
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2014-12-01
    '''
    def convert_encoding(self, data, new_coding = 'UTF-8'):
        encoding = cchardet.detect(data)['encoding']
        if new_coding.upper() != encoding.upper():
            data = data.decode(encoding, data).encode(new_coding)
        return data

    '''
    Funcion para validar los xml generados contra el esquema que le corresponda
    segun el tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def xml_validator(self, some_xml_string, validacion='doc'):
        if 1==1:
            validacion_type = {
                'doc': 'DTE_v10.xsd',
                'env': 'EnvioDTE_v10.xsd',
                'recep' : 'Recibos_v10.xsd',
                'env_recep' : 'EnvioRecibos_v10.xsd',
                'env_resp': 'RespuestaEnvioDTE_v10.xsd',
                'sig': 'xmldsignature_v10.xsd'
            }
            xsd_file = xsdpath+validacion_type[validacion]
            try:
                schema = etree.XMLSchema(file=xsd_file)
                parser = objectify.makeparser(schema=schema)
                objectify.fromstring(some_xml_string, parser)
                return True
            except XMLSyntaxError as e:
                raise Warning(_('XML Malformed Error %s') % e.args)

    '''
    Funcion usada en autenticacion en SII
    Obtencion de la semilla desde el SII.
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-04-01
    '''
    def get_seed(self, company_id):
        #En caso de que haya un problema con la validación de certificado del sii ( por una mala implementación de ellos)
        #esto omite la validacion
        if company_id.dte_service_provider == 'SIIHOMO':
            import ssl
            ssl._create_default_https_context = ssl._create_unverified_context
        url = server_url[company_id.dte_service_provider] + 'CrSeed.jws?WSDL'
        ns = 'urn:'+server_url[company_id.dte_service_provider] + 'CrSeed.jws'
        _server = SOAPProxy(url, ns)
        root = etree.fromstring(_server.getSeed())
        semilla = root[0][0].text
        return semilla

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para realizar el envio del token
    Previo a realizar su firma
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_seed(self, seed):
        xml = u'''<getToken>
<item>
<Semilla>{}</Semilla>
</item>
</getToken>
'''.format(seed)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para envolver el DTE
    Previo a realizar su firma (1)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_doc(self, doc):
        xml = '''<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
{}
</DTE>'''.format(doc)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Creacion de plantilla xml para envolver el Envio de DTEs
    Previo a realizar su firma (2da)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_env(self, doc):
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<EnvioDTE xmlns="http://www.sii.cl/SiiDte" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="http://www.sii.cl/SiiDte EnvioDTE_v10.xsd" \
version="1.0">
{}
</EnvioDTE>'''.format(doc)
        return xml

    '''
    Funcion usada en autenticacion en SII
    Insercion del nodo de firma (1ra) dentro del DTE
    Una vez firmado.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_doc1(self, doc, sign):
        xml = doc.replace('</DTE>', '') + sign + '</DTE>'
        return xml

    '''
    Funcion usada en autenticacion en SII
    Insercion del nodo de firma (2da) dentro del DTE
    Una vez firmado.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_env1(self, doc, sign):
        xml = doc.replace('</EnvioDTE>', '') + sign + '</EnvioDTE>'
        return xml

    def append_sign_recep(self, doc, sign):
        xml = doc.replace('</Recibo>', '') + sign + '</Recibo>'
        return xml

    def append_sign_env_recep(self, doc, sign):
        xml = doc.replace('</EnvioRecibos>', '') + sign + '</EnvioRecibos>'
        return xml

    def append_sign_env_resp(self, doc, sign):
        xml = doc.replace('</RespuestaDTE>', '') + sign + '</RespuestaDTE>'
        return xml

    '''
    Funcion usada en autenticacion en SII
    Firma de la semilla utilizando biblioteca signxml
    De autoria de Andrei Kislyuk https://github.com/kislyuk/signxml
    (en este caso particular esta probada la efectividad de la libreria)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def sign_seed(self, message, privkey, cert):
        doc = etree.fromstring(message)
        signed_node = xmldsig(
            doc, digest_algorithm=u'sha1').sign(
            method=methods.enveloped, algorithm=u'rsa-sha1',
            key=privkey.encode('ascii'),
            cert=cert)
        msg = etree.tostring(
            signed_node, pretty_print=True).replace('ds:', '')
        return msg

    '''
    Funcion usada en autenticacion en SII
    Obtencion del token a partir del envio de la semilla firmada
    Basada en función de ejemplo mostrada en el sitio edreams.cl
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_token(self, seed_file,company_id):
        url = server_url[company_id.dte_service_provider] + 'GetTokenFromSeed.jws?WSDL'
        ns = 'urn:'+ server_url[company_id.dte_service_provider] +'GetTokenFromSeed.jws'
        _server = SOAPProxy(url, ns)
        tree = etree.fromstring(seed_file)
        ss = etree.tostring(tree, pretty_print=True, encoding='iso-8859-1')
        respuesta = etree.fromstring(_server.getToken(ss))
        token = respuesta[0][0].text
        return token

    def ensure_str(self,x, encoding="utf-8", none_ok=False):
        if none_ok is True and x is None:
            return x
        if not isinstance(x, str):
            x = x.decode(encoding)
        return x

    def long_to_bytes(self, n, blocksize=0):
        """long_to_bytes(n:long, blocksize:int) : string
        Convert a long integer to a byte string.
        If optional blocksize is given and greater than zero, pad the front of the
        byte string with binary zeros so that the length is a multiple of
        blocksize.
        """
        # after much testing, this algorithm was deemed to be the fastest
        s = b''
        n = long(n)  # noqa
        import struct
        pack = struct.pack
        while n > 0:
            s = pack(b'>I', n & 0xffffffff) + s
            n = n >> 32
        # strip off leading zeros
        for i in range(len(s)):
            if s[i] != b'\000'[0]:
                break
        else:
            # only happens when n == 0
            s = b'\000'
            i = 0
        s = s[i:]
        # add back some pad bytes.  this could be done more efficiently w.r.t. the
        # de-padding being done above, but sigh...
        if blocksize > 0 and len(s) % blocksize:
            s = (blocksize - len(s) % blocksize) * b'\000' + s
        return s

    def sign_full_xml(self, message, privkey, cert, uri, type='doc'):
        doc = etree.fromstring(message)
        string = etree.tostring(doc[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        digest = base64.b64encode(self.digest(mess))
        reference_uri='#'+uri
        signed_info = Element("SignedInfo")
        c14n_method = SubElement(signed_info, "CanonicalizationMethod", Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')
        sign_method = SubElement(signed_info, "SignatureMethod", Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1')
        reference = SubElement(signed_info, "Reference", URI=reference_uri)
        transforms = SubElement(reference, "Transforms")
        SubElement(transforms, "Transform", Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
        digest_method = SubElement(reference, "DigestMethod", Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
        digest_value = SubElement(reference, "DigestValue")
        digest_value.text = digest
        signed_info_c14n = etree.tostring(signed_info,method="c14n",exclusive=False,with_comments=False,inclusive_ns_prefixes=None)
        if type in ['doc','recep']:
            att = 'xmlns="http://www.w3.org/2000/09/xmldsig#"'
        else:
            att = 'xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        #@TODO Find better way to add xmlns:xsi attrib
        signed_info_c14n = signed_info_c14n.replace("<SignedInfo>","<SignedInfo " + att + ">")
        sig_root = Element("Signature",attrib={'xmlns':'http://www.w3.org/2000/09/xmldsig#'})
        sig_root.append(etree.fromstring(signed_info_c14n))
        signature_value = SubElement(sig_root, "SignatureValue")
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        import OpenSSL
        from OpenSSL.crypto import *
        type_ = FILETYPE_PEM
        key=OpenSSL.crypto.load_privatekey(type_,privkey.encode('ascii'))
        signature= OpenSSL.crypto.sign(key,signed_info_c14n,'sha1')
        signature_value.text =textwrap.fill(base64.b64encode(signature),64)
        key_info = SubElement(sig_root, "KeyInfo")
        key_value = SubElement(key_info, "KeyValue")
        rsa_key_value = SubElement(key_value, "RSAKeyValue")
        modulus = SubElement(rsa_key_value, "Modulus")
        key = load_pem_private_key(privkey.encode('ascii'),password=None, backend=default_backend())
        modulus.text =  textwrap.fill(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().n)),64)
        exponent = SubElement(rsa_key_value, "Exponent")
        exponent.text = self.ensure_str(base64.b64encode(self.long_to_bytes(key.public_key().public_numbers().e)))
        x509_data = SubElement(key_info, "X509Data")
        x509_certificate = SubElement(x509_data, "X509Certificate")
        x509_certificate.text = '\n'+textwrap.fill(cert,64)
        msg = etree.tostring(sig_root)
        msg = msg if self.xml_validator(msg, 'sig') else ''
        if type=='doc':
            fulldoc = self.create_template_doc1(message, msg)
        if type=='env':
            fulldoc = self.create_template_env1(message,msg)
        if type=='recep':
            fulldoc = self.append_sign_recep(message,msg)
        if type=='env_recep':
            fulldoc = self.append_sign_env_recep(message,msg)
        if type=='env_resp':
            fulldoc = self.append_sign_env_resp(message,msg)
        fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        return fulldoc

    def get_digital_signature_pem(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])
            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert,
            'rut_envia': obj.subject_serial_number
            }
        return signature_data

    def get_digital_signature(self, comp_id):
        obj = self.env['res.users'].browse([self.env.user.id])
        if not obj.cert:
            obj = self.env['res.company'].browse([comp_id.id])
            if not obj.cert:
                obj = self.env['res.users'].search(domain=[("authorized_users_ids","=", self.env.user.id)])
            if not obj.cert or not self.env.user.id in obj.authorized_users_ids.ids:
                return False
        signature_data = {
            'subject_name': obj.name,
            'subject_serial_number': obj.subject_serial_number,
            'priv_key': obj.priv_key,
            'cert': obj.cert}
        return signature_data

    '''
    Funcion usada en SII
    Toma los datos referentes a la resolución SII que autoriza a
    emitir DTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_resolution_data(self, comp_id):
        resolution_data = {
            'dte_resolution_date': comp_id.dte_resolution_date,
            'dte_resolution_number': comp_id.dte_resolution_number}
        return resolution_data

    @api.multi
    def send_xml_file(self, envio_dte=None, file_name="envio",company_id=False):
        if not company_id.dte_service_provider:
            raise UserError(_("Not Service provider selected!"))
        try:
            signature_d = self.get_digital_signature_pem(
                company_id)
            seed = self.get_seed(company_id)
            template_string = self.create_template_seed(seed)
            seed_firmado = self.sign_seed(
                template_string, signature_d['priv_key'],
                signature_d['cert'])
            token = self.get_token(seed_firmado,company_id)
        except:
            raise Warning(connection_status[response.e])
            return {'sii_result': 'NoEnviado'}

        url = 'https://palena.sii.cl'
        if company_id.dte_service_provider == 'SIIHOMO':
            url = 'https://maullin.sii.cl'
        post = '/cgi_dte/UPL/DTEUpload'
        headers = {
            'Accept': 'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-powerpoint, application/ms-excel, application/msword, */*',
            'Accept-Language': 'es-cl',
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Mozilla/4.0 (compatible; PROG 1.0; Windows NT 5.0; YComp 5.0.2.4)',
            'Referer': '{}'.format(company_id.website),
            'Connection': 'Keep-Alive',
            'Cache-Control': 'no-cache',
            'Cookie': 'TOKEN={}'.format(token),
        }
        params = collections.OrderedDict()
        params['rutSender'] = signature_d['subject_serial_number'][:8]
        params['dvSender'] = signature_d['subject_serial_number'][-1]
        params['rutCompany'] = company_id.vat[2:-1]
        params['dvCompany'] = company_id.vat[-1]
        params['archivo'] = (file_name,envio_dte,"text/xml")
        multi  = urllib3.filepost.encode_multipart_formdata(params)
        headers.update({'Content-Length': '{}'.format(len(multi[0]))})
        response = pool.request_encode_body('POST', url+post, params, headers)
        retorno = {'sii_xml_response': response.data, 'sii_result': 'NoEnviado','sii_send_ident':''}
        if response.status != 200:
            return retorno
        respuesta_dict = xmltodict.parse(response.data)
        if respuesta_dict['RECEPCIONDTE']['STATUS'] != '0':
            _logger.info(connection_status[respuesta_dict['RECEPCIONDTE']['STATUS']])
        else:
            retorno.update({'sii_result': 'Enviado','sii_send_ident':respuesta_dict['RECEPCIONDTE']['TRACKID']})
        return retorno

    '''
    Funcion para descargar el xml en el sistema local del usuario
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    @api.multi
    def get_xml_file(self):
        filename = (self.document_number+'.xml').replace(' ','')
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=account.invoice\
&field=sii_xml_request&id=%s&filename=%s' % (self.id,filename),
            'target': 'self',
        }

    '''
    Funcion para descargar el folio tomando el valor desde la secuencia
    correspondiente al tipo de documento.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_folio(self, inv):
        # saca el folio directamente de la secuencia
        return int(inv.sii_document_number)

    '''
         Se Retorna el CAF que corresponda a la secuencia, independiente del estado
         ya que si se suben 2 CAF y uno está por terminar y se hace un evío masivo
         Deja fuera Los del antiguo CAF, que son válidos aún, porque no se han enviado; y arroja Error
         de que la secuencia no está en el rango del CAF
    '''
    def get_caf_file(self, inv):
        caffiles = inv.journal_document_class_id.sequence_id.dte_caf_ids
        folio = self.get_folio(inv)
        for caffile in caffiles:
            post = base64.b64decode(caffile.caf_file)
            post = xmltodict.parse(post.replace(
                '<?xml version="1.0"?>','',1))
            folio_inicial = post['AUTORIZACION']['CAF']['DA']['RNG']['D']
            folio_final = post['AUTORIZACION']['CAF']['DA']['RNG']['H']
            if folio in range(int(folio_inicial), (int(folio_final)+1)):
                return post
        if not caffiles:
            raise Warning(_('''There is no CAF file available or in use \
for this Document. Please enable one.'''))

        if folio > int(folio_final):
            msg = '''El folio de este documento: {} está fuera de rango \
del CAF vigente (desde {} hasta {}). Solicite un nuevo CAF en el sitio \
www.sii.cl'''.format(folio, folio_inicial, folio_final)
            # defino el status como "spent"
            caffile.status = 'spent'
            raise UserError(_(msg))
        return False

    '''
    Funcion para reformateo del vat desde modo Odoo (dos digitos pais sin guion)
    a valor sin puntuacion con guion
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def format_vat(self, value):
        ''' Se Elimina el 0 para prevenir problemas con el sii, ya que las muestras no las toma si va con
        el 0 , y tambien internamente se generan problemas'''
        rut = value[:10] + '-' + value[10:]
        rut = rut.replace('CL0','').replace('CL','')
        return rut

    '''
    Funcion creacion de imagen pdf417 basada en biblioteca elaphe
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def pdf417bc(self, ted):
        bc = barcode(
            'pdf417',
            ted,
            options = dict(
                compact = False,
                eclevel = 5,
                columns = 13,
                rowmult = 2,
                rows = 3
            ),
            margin=20,
            scale=1
        )
        return bc

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def digest(self, data):
        sha1 = hashlib.new('sha1', data)
        return sha1.digest()

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def signrsa(self, MESSAGE, KEY, digst=''):
        KEY = KEY.encode('ascii')
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        if digst == '':
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64eDigesncode(rsa_m.e)}
        else:
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

    '''
    Funcion usada en SII
    para firma del timbre (dio errores de firma para el resto de los doc)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-03-01
    '''
    def signmessage(self, MESSAGE, KEY, pubk='', digst=''):
        rsa = M2Crypto.EVP.load_key_string(KEY)
        rsa.reset_context(md='sha1')
        rsa_m = rsa.get_rsa()
        rsa.sign_init()
        rsa.sign_update(MESSAGE)
        FRMT = base64.b64encode(rsa.sign_final())
        if digst == '':
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e)}
        else:
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

    '''
    Definicion de extension de modelo de datos para account.invoice
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2015-02-01
    '''
    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together')

    sii_barcode = fields.Char(
        copy=False,
        string=_('SII Barcode'),
        readonly=True,
        help='SII Barcode Name')

    sii_barcode_img = fields.Binary(
        copy=False,
        string=_('SII Barcode Image'),
        help='SII Barcode Image in PDF417 format')

    sii_message = fields.Text(
        string='SII Message',
        copy=False)
    sii_xml_request = fields.Text(
        string='SII XML Request',
        copy=False)
    sii_xml_response = fields.Text(
        string='SII XML Response',
        copy=False)
    sii_send_ident = fields.Text(
        string='SII Send Identification',
        copy=False)
    sii_result = fields.Selection([
        ('', 'n/a'),
        ('NoEnviado', 'No Enviado'),
        ('Enviado', 'Enviado'),
        ('Aceptado', 'Aceptado'),
        ('Rechazado', 'Rechazado'),
        ('Reparo', 'Reparo'),
        ('Proceso', 'Proceso'),
        ('Reenviar', 'Reenviar'),
        ('Anulado', 'Anulado')],
        'Resultado',
        readonly=True,
        states={'draft': [('readonly', False)]},
        copy=False,
        help="SII request result",
        default = '')
    canceled = fields.Boolean(string="Canceled?")
    estado_recep_dte = fields.Selection(
        [
            ('no_revisado','No Revisado'),
            ('0','Conforme'),
            ('1','Error de Schema'),
            ('2','Error de Firma'),
            ('3','RUT Receptor No Corresponde'),
            ('90','Archivo Repetido'),
            ('91','Archivo Ilegible'),
            ('99','Envio Rechazado - Otros')
        ],string="Estado de Recepcion del Envio")
    estado_recep_glosa = fields.Char(string="Información Adicional del Estado de Recepción")
    sii_send_file_name = fields.Char(string="Send File Name")

    @api.multi
    def get_related_invoices_data(self):
        """
        List related invoice information to fill CbtesAsoc.
        """
        self.ensure_one()
        rel_invoices = self.search([
            ('number', '=', self.origin),
            ('state', 'not in',
                ['draft', 'proforma', 'proforma2', 'cancel'])])
        return rel_invoices

    def _acortar_str(self, texto, size=1):
        c = 0
        cadena = ""
        while c < size and c < len(texto):
            cadena += texto[c]
            c += 1
        return cadena

    @api.multi
    def get_barcode(self, inv,  dte_service, no_product=False):
        ted = False
        folio = self.get_folio(inv)
        result['TED']['DD']['RE'] = inv.format_vat(inv.company_id.vat)
        result['TED']['DD']['TD'] = inv.sii_document_class_id.sii_code
        result['TED']['DD']['F']  = folio
        result['TED']['DD']['FE'] = inv.date_invoice
        if not inv.partner_id.vat:
            raise UserError(_("Fill Partner VAT"))
        result['TED']['DD']['RR'] = inv.format_vat(inv.partner_id.vat)
        if not no_product:
            result['TED']['DD']['RSR'] = self._acortar_str(inv.partner_id.name,40)
        result['TED']['DD']['MNT'] = int(round(inv.amount_total))
        if no_product:
            result['TED']['DD']['MNT'] = 0
        if not no_product:
            for line in inv.invoice_line_ids:
                result['TED']['DD']['IT1'] = self._acortar_str(line.product_id.name,40)
                if line.product_id.default_code:
                    result['TED']['DD']['IT1'] = self._acortar_str(line.product_id.name.replace('['+line.product_id.default_code+'] ',''),40)
                break

        resultcaf = self.get_caf_file(inv)
        result['TED']['DD']['CAF'] = resultcaf['AUTORIZACION']['CAF']
        dte = result['TED']['DD']
        ddxml = '<DD>'+dicttoxml.dicttoxml(
            dte, root=False, attr_type=False).replace(
            '<key name="@version">1.0</key>','',1).replace(
            '><key name="@version">1.0</key>',' version="1.0">',1).replace(
            '><key name="@algoritmo">SHA1withRSA</key>',
            ' algoritmo="SHA1withRSA">').replace(
            '<key name="#text">','').replace(
            '</key>','').replace('<CAF>','<CAF version="1.0">')+'</DD>'
        ddxml = inv.convert_encoding(ddxml, 'utf-8')
        keypriv = (resultcaf['AUTORIZACION']['RSASK']).encode(
            'latin-1').replace('\t','')
        keypub = (resultcaf['AUTORIZACION']['RSAPUBK']).encode(
            'latin-1').replace('\t','')
        #####
        ## antes de firmar, formatear
        root = etree.XML( ddxml )
        ##
        # formateo sin remover indents
        ddxml = etree.tostring(root)
        timestamp = self.time_stamp()
        ddxml = ddxml.replace('2014-04-24T12:02:20', timestamp)
        frmt = inv.signmessage(ddxml, keypriv, keypub)['firma']
        ted = (
            '''<TED version="1.0">{}<FRMT algoritmo="SHA1withRSA">{}\
</FRMT></TED>''').format(ddxml, frmt)
        root = etree.XML(ted)
        inv.sii_barcode = ted
        image = False
        if ted:
            barcodefile = StringIO()
            image = inv.pdf417bc(ted)
            image.save(barcodefile,'PNG')
            data = barcodefile.getvalue()
            inv.sii_barcode_img = base64.b64encode(data)
        ted  = ted + '<TmstFirma>{}</TmstFirma>'.format(timestamp)
        return ted

    @api.multi
    def do_dte_send_invoice(self, n_atencion="612122"):
        dicttoxml.set_debug(False)
        cant_doc_batch = 0
        DTEs = {}
        count = 0
        clases = {}
        company_id = False
        for inv in self.with_context(lang='es_CL'):
            try:
                signature_d = self.get_digital_signature(inv.company_id)
            except:
                raise Warning(_('''There is no Signer Person with an \
            authorized signature for you in the system. Please make sure that \
            'user_signature_key' module has been installed and enable a digital \
            signature, for you or make the signer to authorize you to use his \
            signature.'''))
            certp = signature_d['cert'].replace(
                BC, '').replace(EC, '').replace('\n', '')
            if inv.sii_document_class_id.dte == False:
                continue
            cant_doc_batch = cant_doc_batch + 1
            dte_service = inv.company_id.dte_service_provider
            ted1 = self.get_barcode(inv, dte_service)
            ted_dict = xmltodict.parse('<TED>' + ted1 + '</TED>')
            folio = ted_dict['TED']['TED']['DD']['F']
            if dte_service in ['', 'NONE']:
                return
            giros_emisor = []
            for turn in inv.company_id.company_activities_ids:
                giros_emisor.extend([{'Acteco': turn.code}])
            line_number = 1
            invoice_lines = []
            no_product = False
            MntExe = 0
            for line in inv.invoice_line_ids:
                if line.product_id.default_code == 'NO_PRODUCT':
                    no_product = True
                lines = collections.OrderedDict()
                lines['NroLinDet'] = line_number
                if line.product_id.default_code and not no_product:
                    lines['CdgItem'] = collections.OrderedDict()
                    lines['CdgItem']['TpoCodigo'] = 'INT1'
                    lines['CdgItem']['VlrCodigo'] = line.product_id.default_code
                ivaIncluido = False
                for t in line.invoice_line_tax_ids:
                    ivaIncluido = t.price_include
                    if t.amount == 0:
                        lines['IndExe'] = 1
                        MntExe += int(round(line.price_subtotal, 0))
                lines['NmbItem'] = self._acortar_str(line.product_id.name,80) #
                lines['DscItem'] = self._acortar_str(line.name, 1000) #descripción más extenza
                if line.product_id.default_code:
                    lines['NmbItem'] = self._acortar_str(line.product_id.name.replace('['+line.product_id.default_code+'] ',''),80)
                qty = int(round(line.quantity, 4))
                if not no_product:
                    lines['QtyItem'] = qty
                if qty == 0 and not no_product:
                    lines['QtyItem'] = 1
                elif qty < 0:
                    raise UserError("NO puede ser menor que 0")
                if not no_product:
                    lines['UnmdItem'] = line.uom_id.name[:4]
                if not no_product and ivaIncluido:
                    lines['PrcItem'] = round((line.price_unit / (1 + (t.amount /100))), 4)
                elif not no_product:
                    lines['PrcItem'] = round(line.price_unit, 4)
                if line.discount > 0:
                    lines['DescuentoPct'] = line.discount
                    lines['DescuentoMonto'] = int(round((((line.discount / 100) * lines['PrcItem'])* qty)))
                if not no_product:
                    lines['MontoItem'] = int(round(line.price_subtotal, 0))
                if no_product:
                    lines['MontoItem'] = 0
                line_number += 1
                invoice_lines.extend([{'Detalle': lines}])
            folio = self.get_folio(inv)
            dte = collections.OrderedDict()
            dte1 = collections.OrderedDict()

            dte['Encabezado'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc']['TipoDTE'] = inv.sii_document_class_id.sii_code
            dte['Encabezado']['IdDoc']['Folio'] = folio
            dte['Encabezado']['IdDoc']['FchEmis'] = inv.date_invoice
            # todo: forma de pago y fecha de vencimiento - opcional
            dte['Encabezado']['IdDoc']['FmaPago'] = inv.forma_pago or 1
            dte['Encabezado']['IdDoc']['FchVenc'] = inv.date_due or datetime.strftime(datetime.now(), '%Y-%m-%d')
            dte['Encabezado']['Emisor'] = collections.OrderedDict()
            dte['Encabezado']['Emisor']['RUTEmisor'] = self.format_vat(inv.company_id.vat)
            dte['Encabezado']['Emisor']['RznSoc'] = inv.company_id.partner_id.name
            dte['Encabezado']['Emisor']['GiroEmis'] = inv.turn_issuer.name[:80]
            # todo: Telefono y Correo opcional
            dte['Encabezado']['Emisor']['Telefono'] = inv.company_id.phone or ''
            dte['Encabezado']['Emisor']['CorreoEmisor'] = inv.company_id.dte_email
            dte['Encabezado']['Emisor']['item'] = giros_emisor # giros de la compañia - codigos
            #@TODO: <CdgSIISucur>077063816</CdgSIISucur> codigo de sucursal
            # no obligatorio si no hay sucursal, pero es un numero entregado
            # por el SII para cada sucursal.
            # este deberia agregarse al "punto de venta" el cual ya esta
            dte['Encabezado']['Emisor']['DirOrigen'] = inv.company_id.street + ' ' +(inv.company_id.street2 or '')
            dte['Encabezado']['Emisor']['CmnaOrigen'] = inv.company_id.city_id.name
            dte['Encabezado']['Emisor']['CiudadOrigen'] = inv.company_id.city
            dte['Encabezado']['Receptor'] = collections.OrderedDict()
            dte['Encabezado']['Receptor']['RUTRecep'] = self.format_vat(inv.partner_id.vat)
            dte['Encabezado']['Receptor']['RznSocRecep'] = inv.partner_id.name
            if not inv.invoice_turn:
                raise UserError(_('Seleccione giro del partner'))
            dte['Encabezado']['Receptor']['GiroRecep'] = inv.invoice_turn.name[:40]
            dte['Encabezado']['Receptor']['DirRecep'] = inv.partner_id.street+ ' ' + (inv.partner_id.street2 or '')
            dte['Encabezado']['Receptor']['CmnaRecep'] = inv.partner_id.city_id.name
            dte['Encabezado']['Receptor']['CiudadRecep'] = inv.partner_id.city
            dte['Encabezado']['Totales'] = collections.OrderedDict()
            if inv.sii_document_class_id.sii_code == 34 or (inv.referencias and inv.referencias[0].sii_referencia_TpoDocRef.sii_code == '34'):
                MntExe = inv.amount_total
                if 'global_discount' in inv and inv.global_discount:
                    MntExe = (MntExe * (1 - (inv.global_discount/100)))
                dte['Encabezado']['Totales']['MntExe'] = int(round(MntExe, 0))
                if  no_product:
                    dte['Encabezado']['Totales']['MntExe'] = 0
            elif inv.amount_untaxed and inv.amount_untaxed != 0:
                IVA = False
                for t in inv.tax_line_ids:
                    if t.tax_id.sii_code in [14, 15]:
                        IVA = t
                if IVA.base > 0:
                    dte['Encabezado']['Totales']['MntNeto'] = int(round((IVA.base), 0))
                if MntExe > 0:
                    dte['Encabezado']['Totales']['MntExe'] = int(round( MntExe))
                if IVA:
                    dte['Encabezado']['Totales']['TasaIVA'] = round(IVA.tax_id.amount,2)
                    dte['Encabezado']['Totales']['IVA'] = int(round(IVA.amount, 0))
                if no_product:
                    dte['Encabezado']['Totales']['MntNeto'] = 0
                    dte['Encabezado']['Totales']['TasaIVA'] = 0
                    dte['Encabezado']['Totales']['IVA'] = 0
                if IVA and IVA.tax_id.sii_code in [15]:
                    dte['Encabezado']['Totales']['ImptoReten'] = collections.OrderedDict()
                    dte['Encabezado']['Totales']['ImptoReten']['TpoImp'] = IVA.tax_id.sii_code
                    dte['Encabezado']['Totales']['ImptoReten']['TasaImp'] = round(IVA.tax_id.amount,2)
                    dte['Encabezado']['Totales']['ImptoReten']['MontoImp'] = int(round(IVA.amount))
            monto_total = int(round(inv.amount_total, 0))
            if no_product:
                monto_total = 0
            dte['Encabezado']['Totales']['MntTotal'] = monto_total
            lin_dr = 1
            dr_lines = []
            if inv.global_discount:# or inv.global_rec:
                dr_line = {}
                dr_line = collections.OrderedDict()
                dr_line['NroLinDR'] = lin_dr
                dr_line['TpoMov'] = 'D'
                if inv.global_discount_detail:
                    dr_line['GlosaDR'] = inv.global_discount_detail
                disc_type = "%"
                if inv.global_discount_type == "amount":
                    disc_type = "$"
                dr_line['TpoValor'] = disc_type
                dr_line['ValorDR'] = round(inv.global_discount,2)
                if inv.sii_document_class_id.sii_code in [34] and (inv.referencias and inv.referencias[0].sii_referencia_TpoDocRef.sii_code == '34'):#solamente si es exento
                    dr_line['IndExeDR'] = 1
                dr_lines.extend([{'DscRcgGlobal':dr_line}])
            lin_ref = 1
            ref_lines = []
            if dte_service == 'SIIHOMO' and isinstance(n_atencion, unicode):
                ref_line = {}
                ref_line = collections.OrderedDict()
                ref_line['NroLinRef'] = lin_ref
                count = count +1
                ref_line['TpoDocRef'] = "SET"
                ref_line['FolioRef'] = folio
                ref_line['FchRef'] = datetime.strftime(datetime.now(), '%Y-%m-%d')
                ref_line['RazonRef'] = "CASO "+n_atencion+"-" + str(inv.sii_batch_number)
                lin_ref = 2
                ref_lines.extend([{'Referencia':ref_line}])
            if inv.referencias :
                for ref in inv.referencias:
                    ref_line = {}
                    ref_line = collections.OrderedDict()
                    ref_line['NroLinRef'] = lin_ref
                    if  ref.sii_referencia_TpoDocRef:
                        ref_line['TpoDocRef'] = ref.sii_referencia_TpoDocRef.sii_code
                        ref_line['FolioRef'] = ref.origen
                    ref_line['FchRef'] = ref.fecha_documento or datetime.strftime(datetime.now(), '%Y-%m-%d')
                    if ref.sii_referencia_CodRef not in ['','none', False]:
                        ref_line['CodRef'] = ref.sii_referencia_CodRef
                    ref_line['RazonRef'] = ref.motivo
                    ref_lines.extend([{'Referencia':ref_line}])
            dte['item'] = invoice_lines
            dte['drlines'] = dr_lines
            dte['reflines'] = ref_lines
            doc_id_number = "F{}T{}".format(folio, inv.sii_document_class_id.sii_code)
            doc_id = '<Documento ID="{}">'.format(doc_id_number)
            dte['TEDd'] = 'TEDTEDTED'
            dte1['Documento ID'] = dte
            xml = dicttoxml.dicttoxml(
                dte1, root=False, attr_type=False).replace('<item>','').replace('</item>','').replace('<reflines>','').replace('</reflines>','').replace('<drlines>','').replace('</drlines>','')

            xml = xml.replace('<TEDd>TEDTEDTED</TEDd>', ted1)

            root = etree.XML( xml )
            xml_pret = etree.tostring(root, pretty_print=True).replace(
'<Documento_ID>', doc_id).replace('</Documento_ID>', '</Documento>')
            envelope_efact = self.convert_encoding(xml_pret, 'ISO-8859-1')
            envelope_efact = self.create_template_doc(envelope_efact)
                            ## firma del documento
            einvoice = self.sign_full_xml(
                envelope_efact, signature_d['priv_key'],
                self.split_cert(certp), doc_id_number)
            #@TODO Mejarorar esto en lo posible
            if not inv.sii_document_class_id.sii_code in clases:
                clases[inv.sii_document_class_id.sii_code] = []
            clases[inv.sii_document_class_id.sii_code].extend([{'id':inv.id, 'envio': einvoice}])
            DTEs.update(clases)
            if not company_id:
                company_id = inv.company_id
            elif company_id.id != inv.company_id.id:
                raise UserError("Está combinando compañías")
            company_id = inv.company_id
            #@TODO hacer autoreconciliación
        file_name = ""
        dtes={}
        SubTotDTE = ''
        resol_data = self.get_resolution_data(company_id)
        signature_d = self.get_digital_signature(company_id)
        RUTEmisor = self.format_vat(company_id.vat)
        for id_class_doc, classes in clases.iteritems():
            NroDte = 0
            for documento in classes:
                doc = self.env['account.invoice'].browse(documento['id'])
                dtes.update({str(doc.sii_batch_number): documento['envio']})
                doc.sii_xml_request = documento['envio']
                NroDte += 1
                file_name += 'F' + str(int(doc.sii_document_number)) + 'T' + str(id_class_doc)
            SubTotDTE += '<SubTotDTE>\n<TpoDTE>' + str(id_class_doc) + '</TpoDTE>\n<NroDTE>'+str(NroDte)+'</NroDTE>\n</SubTotDTE>\n'
        file_name += ".xml"
        documentos =""
        for key in sorted(dtes.iterkeys()):
            documentos += '\n'+dtes[key]
        # firma del sobre
        RUTRecep = "60803000-K" # RUT SII
        dtes = self.create_template_envio( RUTEmisor, RUTRecep,
            resol_data['dte_resolution_date'],
            resol_data['dte_resolution_number'],
            self.time_stamp(), documentos, signature_d,SubTotDTE )
        envio_dte  = self.create_template_env(dtes)
        envio_dte = self.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            'SetDoc', 'env')
        result = self.send_xml_file(envio_dte, file_name, company_id)
        for inv in self:
            inv.write({'sii_xml_response':result['sii_xml_response'],
                'sii_send_ident':result['sii_send_ident'],
                'sii_result': result['sii_result'],
                'sii_xml_request':envio_dte,
                'sii_send_file_name' : file_name,
                })


    def _get_send_status(self, track_id, signature_d,token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws'
        _server = SOAPProxy(url, ns)
        rut = self.format_vat(self.company_id.vat)
        respuesta = _server.getEstUp(rut[:8], str(rut[-1]),track_id,token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        status = False
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "-11":
            if resp['SII:RESPUESTA']['SII:RESP_HDR']['ERR_CODE'] == "2":
                status =  {'warning':{'title':_('Estado -11'), 'message': _("Estado -11: Espere a que sea aceptado por el SII, intente en 5s más")}}
            else:
                status =  {'warning':{'title':_('Estado -11'), 'message': _("Estado -11: error 1Algo a salido mal, revisar carátula")}}
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.sii_result = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.sii_result = "Rechazado"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.sii_result = "Rechazado"
            status = {'warning':{'title':_('Error RCT'), 'message': _(resp['SII:RESPUESTA']['GLOSA'])}}
        return status

    def _get_dte_status(self, signature_d, token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstDte.jws'
        _server = SOAPProxy(url, ns)
        receptor = self.format_vat(self.partner_id.vat)
        date_invoice = datetime.strptime(self.date_invoice, "%Y-%m-%d").strftime("%d-%m-%Y")
        rut = signature_d['subject_serial_number']
        respuesta = _server.getEstDte(rut[:8], str(rut[-1]),
                self.company_id.vat[2:-1],self.company_id.vat[-1], receptor[:8],receptor[2:-1],str(self.sii_document_class_id.sii_code), str(self.sii_document_number),
                date_invoice, str(self.amount_total),token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == '2':
            status = {'warning':{'title':_("Error code: 2"), 'message': _(resp['SII:RESPUESTA']['SII:RESP_HDR']['GLOSA'])}}
            return status
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "EPR":
            self.sii_result = "Proceso"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['RECHAZADOS'] == "1":
                self.sii_result = "Rechazado"
            if resp['SII:RESPUESTA']['SII:RESP_BODY']['REPARO'] == "1":
                self.sii_result = "Reparo"
        elif resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "RCT":
            self.sii_result = "Rechazado"

    @api.multi
    def ask_for_dte_status(self):
        try:
            signature_d = self.get_digital_signature_pem(
                self.company_id)
            seed = self.get_seed(self.company_id)
            template_string = self.create_template_seed(seed)
            seed_firmado = self.sign_seed(
                template_string, signature_d['priv_key'],
                signature_d['cert'])
            token = self.get_token(seed_firmado,self.company_id)
        except:
            raise Warning(connection_status[response.e])
        xml_response = xmltodict.parse(self.sii_xml_response)
        if self.sii_result == 'Enviado':
            status = self._get_send_status(self.sii_send_ident, signature_d, token)
            if self.sii_result != 'Proceso':
                return status
        return self._get_dte_status(signature_d, token)

    def _read_xml(self):
        xml = xmltodict.parse(self.sii_xml_request)
        return xml

    def _check_digest_caratula(self):
        xml = etree.fromstring(self.sii_xml_request.encode('UTF-8'))
        string = etree.tostring(xml[0])
        mess = etree.tostring(etree.fromstring(string), method="c14n")
        our = base64.b64encode(self.digest(mess))
        if our != xml[1][0][2][2].text:
            return 2, 'Envio Rechazado - Error de Firma'
        return 0, ''

    def _check_digest_dte(self, dte):
        xml = etree.fromstring(self.sii_xml_request.encode('UTF-8'))
        for d in xml[0]:
            if d != xml[0][0] and d[0][0][0][0].text == dte['Encabezado']['IdDoc']['TipoDTE'] and d[0][0][0][1].text == dte['Encabezado']['IdDoc']['Folio']:
                string = etree.tostring(d[0])
                mess = etree.tostring(etree.fromstring(string), method="c14n").replace(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"','')# el replace es necesario debido a que python lo agrega solo
                our = base64.b64encode(self.digest(mess))
                if our != d[1][0][2][2].text:
                    return 1, 'DTE No Recibido - Error de Firma'
        return 0, 'DTE Recibido OK'

    def _validar_caratula(self, cara):
        if not self.env['res.company'].search([('vat','like', cara['RutReceptor'].replace('-',''))]):#se usa like porque sii envía rut sin 0 adelante
            return 3, 'Rut no corresponde a nuestra empresa'
        partner_id = self.env['res.partner'].search([('vat','like', cara['RutEmisor'].replace('-',''))])
        if not partner_id:
            return 2, 'Rut no coincide con los registros'
        try:
            self.xml_validator(self.sii_xml_request.encode('UTF-8'), 'env')
        except:
            return 1, 'Envio Rechazado - Error de Schema'
        #for SubTotDTE in cara['SubTotDTE']:
        #    sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(SubTotDTE['TipoDTE']))])
        #    if not sii_document_class:
        #        return  99, 'Tipo de documento desconocido'
        return 0, ''

    def _validar(self, doc):
        cara, glosa = self._validar_caratula(doc[0][0]['Caratula'])
        if cara != 0:
            return cara
        return 0, ''

    def _validar_dte(self, doc):
        res = collections.OrderedDict()
        res['TipoDTE'] = doc['Encabezado']['IdDoc']['TipoDTE']
        res['Folio'] = doc['Encabezado']['IdDoc']['Folio']
        res['FchEmis'] = doc['Encabezado']['IdDoc']['FchEmis']
        res['RUTEmisor'] = doc['Encabezado']['Emisor']['RUTEmisor']
        res['RUTRecep'] = doc['Encabezado']['Receptor']['RUTRecep']
        res['MntTotal'] = doc['Encabezado']['Totales']['MntTotal']
        partner_id = self.env['res.partner'].search([('vat','like', doc['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(doc['Encabezado']['IdDoc']['TipoDTE']))])
        res['EstadoRecepDTE'] = 0
        res['RecepDTEGlosa'] = 'DTE Recibido OK'
        res['EstadoRecepDTE'], res['RecepDTEGlosa'] = self._check_digest_dte(doc)
        if not sii_document_class:
            res['EstadoRecepDTE'] = 99
            res['RecepDTEGlosa'] = 'Tipo de documento desconocido'
            return res
        docu = self.env['account.invoice'].search([('reference','=', doc['Encabezado']['IdDoc']['Folio']),('partner_id','=',partner_id.id),('sii_document_class_id','=',sii_document_class.id)])
        if not docu or doc['Encabezado']['Receptor']['RUTRecep'] != self.format_vat(docu.company_id.vat):
            res['EstadoRecepDTE'] = 3
            res['RecepDTEGlosa'] = 'Rut no corresponde a la empresa esperada'
            return res
        if docu.reference != doc['Encabezado']['IdDoc']['Folio']:
            res['EstadoRecepDTE'] = 99
            res['RecepDTEGlosa'] = 'Folio desconocido'
        return res

    def _validar_dtes(self):
        envio = self._read_xml()
        size = len(envio['EnvioDTE']['SetDTE']['DTE'])
        if size == 1:
            res = {'RecepcionDTE' : self._validar_dte(envio['EnvioDTE']['SetDTE']['DTE']['Documento'])}
        else:
            res = []
            for doc in envio['EnvioDTE']['SetDTE']['DTE']:
                res.extend([ {'RecepcionDTE' : self._validar_dte(doc['Documento'])} ])
        return res

    def _caratula_respuesta(self, RutResponde, IdRespuesta="1", NroDetalles=0):
        caratula = collections.OrderedDict()
        caratula['RutResponde'] = RutResponde
        caratula['RutRecibe'] = self.format_vat( self.partner_id.vat)
        caratula['IdRespuesta'] = IdRespuesta
        caratula['NroDetalles'] = NroDetalles
        caratula['NmbContacto'] = self.env.user.partner_id.name
        caratula['FonoContacto'] = self.env.user.partner_id.phone
        caratula['MailContacto'] = self.env.user.partner_id.email
        caratula['TmstFirmaResp'] = self.time_stamp()
        return caratula

    def _receipt(self, IdRespuesta):
        envio = self._read_xml()
        xml = etree.fromstring(self.sii_xml_request.encode('UTF-8'))
        resp = collections.OrderedDict()
        resp['NmbEnvio'] = self.sii_send_file_name
        resp['FchRecep'] = self.time_stamp()
        resp['CodEnvio'] = self._acortar_str(IdRespuesta + self.number[15:], 10)
        resp['EnvioDTEID'] = xml[0].attrib['ID']
        resp['Digest'] = xml[1][0][2][2].text
        EstadoRecepEnv, RecepEnvGlosa = self._validar_caratula(envio['EnvioDTE']['SetDTE']['Caratula'])
        if EstadoRecepEnv == 0:
            EstadoRecepEnv, RecepEnvGlosa = self._check_digest_caratula()
        resp['RutEmisor'] = envio['EnvioDTE']['SetDTE']['Caratula']['RutEmisor']
        resp['RutReceptor'] = envio['EnvioDTE']['SetDTE']['Caratula']['RutReceptor']
        resp['EstadoRecepEnv'] = EstadoRecepEnv
        resp['RecepEnvGlosa'] = RecepEnvGlosa
        resp['NroDTE'] = len(envio['EnvioDTE']['SetDTE']['DTE'])
        resp['item'] = self._validar_dtes()
        return resp

    def _RecepcionEnvio(self, Caratula, resultado):
        resp='''
        <RespuestaDTE version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte RespuestaEnvioDTE_v10.xsd" >
            <Resultado ID="Odoo_resp">
                <Caratula version="1.0">
                    {0}
                </Caratula>
                    {1}
            </Resultado>
        </RespuestaDTE>'''.format(Caratula,resultado)
        return resp

    def do_receipt_deliver(self):
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        for inv in self:
            if inv.estado_recep_dte not in ['0']:
                try:
                    signature_d = self.get_digital_signature(inv.company_id)
                except:
                    raise Warning(_('''There is no Signer Person with an \
                authorized signature for you in the system. Please make sure that \
                'user_signature_key' module has been installed and enable a digital \
                signature, for you or make the signer to authorize you to use his \
                signature.'''))
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                recep = inv._receipt(IdRespuesta)
                envio = self._read_xml()
                NroDetalles = len(envio['EnvioDTE']['SetDTE']['DTE'])
        dicttoxml.set_debug(False)
        resp_dtes = dicttoxml.dicttoxml(recep, root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        RecepcionEnvio = '''<RecepcionEnvio>
                    {0}
                    </RecepcionEnvio>
                    '''.format(resp_dtes)
        caratula = dicttoxml.dicttoxml(self._caratula_respuesta(self.format_vat(inv.company_id.vat), IdRespuesta, NroDetalles), root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        resp = self._RecepcionEnvio(caratula, RecepcionEnvio )

        respuesta = self.sign_full_xml(
            resp, signature_d['priv_key'], certp,
            'Odoo_resp', 'env_resp')
        raise UserError(respuesta)

    def _validar_dte_en_envio(self, doc, IdRespuesta):
        res = collections.OrderedDict()
        res['TipoDTE'] = doc['Encabezado']['IdDoc']['TipoDTE']
        res['Folio'] = doc['Encabezado']['IdDoc']['Folio']
        res['FchEmis'] = doc['Encabezado']['IdDoc']['FchEmis']
        res['RUTEmisor'] = doc['Encabezado']['Emisor']['RUTEmisor']
        res['RUTRecep'] = doc['Encabezado']['Receptor']['RUTRecep']
        res['MntTotal'] = doc['Encabezado']['Totales']['MntTotal']
        res['CodEnvio'] = str(IdRespuesta) + str(doc['Encabezado']['IdDoc']['Folio'])
        partner_id = self.env['res.partner'].search([('vat','like', doc['Encabezado']['Emisor']['RUTEmisor'].replace('-',''))])
        sii_document_class = self.env['sii.document_class'].search([('sii_code','=', str(doc['Encabezado']['IdDoc']['TipoDTE']))])
        res['EstadoDTE'] = 0
        res['EstadoDTEGlosa'] = 'DTE Aceptado OK'
        if not sii_document_class:
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
            return res

        if doc['Encabezado']['Receptor']['RUTRecep'] != self.company_id.partner_id.document_number:
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
            return res

        if int(round(self.amount_total)) != int(round(doc['Encabezado']['Totales']['MntTotal'])):
            res['EstadoDTE'] = 2
            res['EstadoDTEGlosa'] = 'DTE Rechazado'
            res['CodRchDsc'] = "-1"
        #@TODO hacer más Validaciones, como por ejemplo, valores por línea
        return res

    def _resultado(self, IdRespuesta):
        envio = self._read_xml()
        size = len(envio['EnvioDTE']['SetDTE']['DTE'])
        if size == 1:
            return {'ResultadoDTE' : self._validar_dte_en_envio(envio['EnvioDTE']['SetDTE']['DTE']['Documento'],IdRespuesta)}
        else:
            for doc in envio['EnvioDTE']['SetDTE']['DTE']:
                if doc['Documento']['Encabezado']['IdDoc']['Folio'] == self.reference:
                    return {'ResultadoDTE' : self._validar_dte_en_envio(doc['Documento'], IdRespuesta)}
        return False

    def _ResultadoDTE(self, Caratula, resultado):
        resp='''
        <RespuestaDTE version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte RespuestaEnvioDTE_v10.xsd" >
            <Resultado ID="Odoo_resp">
                <Caratula version="1.0">
                    {0}
                </Caratula>
                    {1}
            </Resultado>
        </RespuestaDTE>'''.format(Caratula,resultado)

        return resp

    def do_validar_comercial(self):
        id_seq = self.env.ref('l10n_cl_dte.response_sequence').id
        IdRespuesta = self.env['ir.sequence'].browse(id_seq).next_by_id()
        for inv in self:
            if inv.estado_recep_dte not in ['0']:
                try:
                    signature_d = self.get_digital_signature(inv.company_id)
                except:
                    raise Warning(_('''There is no Signer Person with an \
                authorized signature for you in the system. Please make sure that \
                'user_signature_key' module has been installed and enable a digital \
                signature, for you or make the signer to authorize you to use his \
                signature.'''))
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                dte = inv._resultado(IdRespuesta)
                envio = self._read_xml()
                NroDetalles = len(envio['EnvioDTE']['SetDTE']['DTE'])
        dicttoxml.set_debug(False)
        ResultadoDTE = dicttoxml.dicttoxml(dte, root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')

        caratula = dicttoxml.dicttoxml(self._caratula_respuesta(self.format_vat(inv.company_id.vat), IdRespuesta, NroDetalles), root=False, attr_type=False).replace('<item>','\n').replace('</item>','\n')
        resp = self._ResultadoDTE(caratula, ResultadoDTE  )

        respuesta = self.sign_full_xml(
            resp, signature_d['priv_key'], certp,
            'Odoo_resp', 'env_resp')
        raise UserError(respuesta)

    def _recep(self, inv, RutFirma, key, cert):
        receipt = collections.OrderedDict()
        receipt['TipoDoc'] = inv.sii_document_class_id.sii_code
        receipt['Folio'] = int(inv.reference)
        receipt['FchEmis'] = inv.date_invoice
        receipt['RUTEmisor'] = self.format_vat(inv.partner_id.vat)
        receipt['RUTRecep'] = self.format_vat(inv.company_id.vat)
        receipt['MntTotal'] = int(round(inv.amount_total))
        receipt['Recinto'] = inv.company_id.street
        receipt['RutFirma'] = RutFirma
        receipt['Declaracion'] = 'El acuse de recibo que se declara en este acto, de acuerdo a lo dispuesto en la letra b) del Art. 4, y la letra c) del Art. 5 de la Ley 19.983, acredita que la entrega de mercaderias o servicio(s) prestado(s) ha(n) sido recibido(s).'
        receipt['TmstFirmaRecibo'] = self.time_stamp()
        id = "T"+str(inv.sii_document_class_id.sii_code)+"F"+str(self.get_folio(inv))
        doc = '''
        <Recibo version="1.0" xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.sii.cl/SiiDte Recibos_v10.xsd" >
            <DocumentoRecibo ID="{0}" >
            {1}
            </DocumentoRecibo>
        </Recibo>
        '''.format(id, dicttoxml.dicttoxml(receipt, root=False, attr_type=False))
        return self.sign_full_xml(
            doc, key, cert,
            'Recibo', 'recep')

    def _envio_recep(self,caratula, recep):
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<EnvioRecibos xmlns='http://www.sii.cl/SiiDte' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:schemaLocation='http://www.sii.cl/SiiDte EnvioRecibos_v10.xsd' version="1.0">
    <SetRecibos ID="SetDteRecibidos">
        <Caratula version="1.0">
        {0}
        </Caratula>
        {1}
    </SetRecibos>
</EnvioRecibos>'''.format(caratula, recep)
        return xml

    def _caratula_recep(self, RutResponde):
        caratula = collections.OrderedDict()
        caratula['RutResponde'] = RutResponde
        caratula['RutRecibe'] = self.format_vat( self.partner_id.vat)
        caratula['NmbContacto'] = self.env.user.partner_id.name
        caratula['FonoContacto'] = self.env.user.partner_id.phone
        caratula['MailContacto'] = self.env.user.partner_id.email
        caratula['TmstFirmaEnv'] = self.time_stamp()
        return caratula

    @api.multi
    def do_receipt(self):
        receipts = ""
        for inv in self:
            if inv.estado_recep_dte not in ['0']:
                try:
                    signature_d = self.get_digital_signature(inv.company_id)
                except:
                    raise Warning(_('''There is no Signer Person with an \
                authorized signature for you in the system. Please make sure that \
                'user_signature_key' module has been installed and enable a digital \
                signature, for you or make the signer to authorize you to use his \
                signature.'''))
                certp = signature_d['cert'].replace(
                    BC, '').replace(EC, '').replace('\n', '')
                receipts += "\n"+self._recep(inv, signature_d['subject_serial_number'],signature_d['priv_key'], certp)
        caratula = dicttoxml.dicttoxml(self._caratula_recep(self.format_vat(inv.company_id.vat)), root=False, attr_type=False)
        envio_dte = self._envio_recep(caratula, receipts)
        envio_dte = self.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            'SetDteRecibidos', 'env_recep')
        raise UserError(envio_dte)
        #result = self.send_xml_file(envio_dte, file_name, company_id)
        from openerp.addons.web.controllers.main import serialize_exception, content_disposition

        headers = [
            ('Content-Type', 'application/xml'),
            ('Content-Disposition', content_disposition(inv.sii_send_file_name)),
            ('charset', 'utf-8'),
        ]
        return request.make_response(
                envio_dte, headers=headers, cookies=None)

    @api.multi
    def wizard_upload(self):
        return {
                'type': 'ir.actions.act_window',
                'res_model': 'sii.dte.upload_xml.wizard',
                'src_model': 'account.invoice',
                'view_mode': 'form',
                'view_type': 'form',
                'views': [(False, 'form')],
                'target': 'new',
                'tag': 'action_upload_xml_wizard'
                }

    @api.multi
    def wizard_validar(self):
        return {
                'type': 'ir.actions.act_window',
                'res_model': 'sii.dte.validar.wizard',
                'src_model': 'account.invoice',
                'view_mode': 'form',
                'view_type': 'form',
                'views': [(False, 'form')],
                'target': 'new',
                'tag': 'action_validar_wizard'
                }

    @api.multi
    def print_cedible(self):
        """ Print Cedible
        """
        return self.env['report'].get_action(self, 'l10n_cl_dte.invoice_cedible')

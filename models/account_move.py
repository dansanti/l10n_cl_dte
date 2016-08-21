# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################


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
#from tests import *
#from suds import WebFault
#from suds.client import Client
# from suds.sax.text import Raw
# import suds.client as sudscl

try:
    from suds.client import Client
except:
    pass
# from suds.transport.https import WindowsHttpAuthenticated
# from suds.cache import ObjectCache

# ejemplo de suds

# intento con urllib3
try:
    import urllib3
except:
    pass

# from urllib3 import HTTPConnectionPool
#urllib3.disable_warnings()
pool = urllib3.PoolManager(timeout=30)
# ca_certs = "/etc/ssl/certs/ca-certificates.crt"
# pool = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=ca_certs)
import textwrap

# from inspect import currentframe, getframeinfo
# estas 2 lineas son para imprimir el numero de linea del script
# (solo para debug)

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
    _inherit = "account.move"

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
                              TmstFirmaEnv, EnvioDTE,signature_d,SubTotDTE,TipoOperacion='VENTA'):
         xml = '''<EnvioLibro ID="SetDoc">
<Caratula version="1.0">
<RutEmisorLibro>{0}</RutEmisorLibro>
<RutEnvia>{1}</RutEnvia>
<PeriodoTributario>{2}</PeriodoTributario>
<FchResol>{3}</FchResol>
<NroResol>{4}</NroResol>
<TipoOperacion>{5}</TipoOperacion>
<TipoLibro>Mensual</TipoLibro>
<TipoEnvio>TOTAL</TipoEnvio>
<TmstFirmaEnv>{5}</TmstFirmaEnv>
{6}</Caratula>
{7}
</EnvioLibro>
'''.format(RutEmisor, signature_d['subject_serial_number'], RutReceptor,
           FchResol,TipoOperacion, NroResol, TmstFirmaEnv, SubTotDTE, EnvioDTE)
        return xml

    '''
    Funcion para convertir la timezone. Realizada para probar si el problema de
    error de firma proviene de la fecha.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def convert_timezone(self, dia, time):
        print(datetime.strftime(datetime.now(), '%Y-%m-%dT%H:%M:%S'))
        print(datetime.strftime(datetime.now() - timedelta(hours=4), '%Y-%m-%dT%H:%M:%S'))
        return datetime.now()

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
    Funcion auxiliar para saber que codificacion tiene el string
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def whatisthis(self, s):
        if isinstance(s, str):
            _logger.info("ordinary string")
        elif isinstance(s, unicode):
            _logger.info("unicode string")
        else:
            _logger.info("not a string")

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
                'sig': 'xmldsignature_v10.xsd',
                'libro': 'LibroCVS_v10.xsd',
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
    Creacion de plantilla xml para envolver el Envio de DTEs
    Previo a realizar su firma (2da)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def create_template_env(self, doc,simplificado=False):
        simp = 'http://www.sii.cl/SiiDte LibroCV_v10.xsd'
        if simplificado:
            simp ='http://www.sii.cl/SiiDte LibroCVS_v10.xsd'
        xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<LibroCompraVenta xmlns="http://www.sii.cl/SiiDte" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="{0}" \
version="1.0">
{1}</LibroCompraVenta>'''.format(simp, doc)
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

    '''
    Funcion usada en SII
    Firma de xml en 1ra y 2da firma (dte y enviodte)
    utilizando biblioteca signxml,
    De autoria de Andrei Kislyuk https://github.com/kislyuk/signxml
    (en este caso particular esta en duda la efectividad de la libreria
    dado que todo parece estar bien pero al momento de envio de la firma
    aparece un error).
    Los valores de tag que devuelve la biblioteca contienen un prefijo "ds"
    el cual es removido para que no de error de validación de schema de firma.
    Notar que no se esta alterando el documento firmado porque lo que se altera
    son solo los nodos de firma para compatibilizar con schema del sii.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def sign_full_xml(self, message, privkey, cert, uri, type='libro'):
        #_logger.info('mensaje de entrada: %s' % message)
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
        if type == 'doc':
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
        #_logger.info('firma......')
        #_logger.info(msg)
        #_logger.info('validacion de firma......')
        msg = msg if self.xml_validator(msg, 'sig') else ''
        if type=='doc':
            fulldoc = self.create_template_doc1(message, msg)
            fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        if type=='env':
            fulldoc = self.create_template_env1(message,msg)
        #_logger.info('documento de salida: %s' % type)
        #_logger.info(fulldoc)
        #_logger.info('entro a validacion: %s' % type)
        fulldoc = fulldoc if self.xml_validator(fulldoc, type) else ''
        return fulldoc

    '''
    Funcion usada en SII
    Lee los parametros de firma tomados desde el usuario corriente.
    En formato PEM
    Requiere la instalacion del addon user_signature_key
    No incorporado en las dependencias deliberadamente
    puesto que se pretende que la opcion de instalar el mismo sea provista
    por el addon l10n_cl_base
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
     @update: Daniel Santibáñez Polanco
     @update : 2016-07-23
     Si no tiene certificado, intenta con el de compañía, si tiene permisos
    '''
    def get_digital_signature_pem(self, comp_id):
        #_logger.info(_('Executing digital signature function in PEM format'))
        #_logger.info('Service provider for this company is %s' % comp_id)
        if comp_id.dte_service_provider in ['SIIHOMO', 'SII']:
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
        else:
            return ''

    '''
    Funcion usada en SII
    Lee los parametros de firma tomados desde el usuario corriente.
    (la firma pura).
    Requiere la instalacion del addon user_signature_key
    No incorporado en las dependencias deliberadamente
    puesto que se pretende que la opcion de instalar el mismo sea provista
    por el addon l10n_cl_base
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_digital_signature(self, comp_id):
        #_logger.info(_('Executing digital signature function'))
        #_logger.info('Service provider for this company is %s' % comp_id)
        if comp_id.dte_service_provider in ['SIIHOMO', 'SII']:
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
            #_logger.info('The signature data is the following %s' % signature_data)
            # todo: chequear si el usuario no tiene firma, si esta autorizado por otro usuario
            return signature_data
        else:
            return ''

    '''
    Funcion usada en SII
    Toma los datos referentes a la resolución SII que autoriza a
    emitir DTE
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    def get_resolution_data(self, comp_id):
        #_logger.info('Entering function get_resolution_data')
        #_logger.info('Service provider for this company is %s' % comp_id.dte_service_provider)
        resolution_data = {
            'dte_resolution_date': comp_id.dte_resolution_date,
            'dte_resolution_number': comp_id.dte_resolution_number}
        return resolution_data

    '''
    Realización del envío de DTE.
    La funcion selecciona el proveedor de servicio de DTE y efectua el envio
    de acuerdo a la integracion del proveedor.
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-06-01
    '''
    @api.multi
    def send_xml_file(self, envio_dte=None, file_name="envio",company_id=False):
        # seteo esta variable para saltear el proceso de envío masivo
        # (esto es un envio con varios documentos)

        #_logger.info('Entering Send XML Function')
        if not company_id.dte_service_provider:
            raise UserError(_("Not Service provider selected!"))
        #_logger.info(
        #    'Service provider is: %s' % company_id.dte_service_provider)
        if company_id.dte_service_provider == 'EFACTURADELSUR':
            host = 'https://www.efacturadelsur.cl'
            post = '/ws/DTE.asmx' # HTTP/1.1
            url = host + post
            #_logger.info('URL to be used %s' % url)
            #_logger.info('Lenght used for forming envelope: %s' % len(self.sii_xml_request))
            response = pool.urlopen('POST', url, headers={
                'Content-Type': 'application/soap+xml',
                'charset': 'utf-8',
                'Content-Length': len(
                    self.sii_xml_request)}, body=self.sii_xml_request)

            #_logger.info(response.status)
            #_logger.info(response.data)
            self.sii_xml_response = response.data
            self.sii_result = 'Enviado'
        elif company_id.dte_service_provider in ['SII', 'SIIHOMO']:#for multicompany
            # en esta etapa el proceso de armado de XML me entrega el xml completo
            # que debo enviar, y no hace falta construirlo
            # Se puede dejar la autenticación completa en esta etapa más adelante
            # estos comentarios eran antes... ahora vamos con un solo envio por invoice
            #   ###### comienzo de bloque de autenticacion #########
            #   ### Hipótesis: un envío por cada RUT de receptor ###
            # all el código estaba indentado más adentro antes....
            #_logger.info(_('Entering individual sending...'))
            if 1==1:
                try:
                    signature_d = self.get_digital_signature_pem(
                        company_id)
                    seed = self.get_seed(company_id)
                    #_logger.info(_("Seed is:  {}").format(seed))
                    template_string = self.create_template_seed(seed)
                    seed_firmado = self.sign_seed(
                        template_string, signature_d['priv_key'],
                        signature_d['cert'])
                    token = self.get_token(seed_firmado,company_id)
                    #_logger.info(_("Token is: {}").format(token))
                except:
                    raise Warning(connection_status[response.e])
            else:
                #except:
                # no pudo hacer el envío
                return {'sii_result': 'NoEnviado'}
            ######### fin de bloque de autenticacion ###########

            ########### inicio del bloque de envio #############
            ###
            url = 'https://palena.sii.cl'
            if company_id.dte_service_provider == 'SIIHOMO':
                url = 'https://maullin.sii.cl'
            post = '/cgi_dte/UPL/DTEUpload'
            # port = 443
            # Armo el encabezado por separado para poder debuggear
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
            file_name = file_name + '.xml'
            params['archivo'] = (file_name,envio_dte,"text/xml")
            multi  = urllib3.filepost.encode_multipart_formdata(params)
            #_logger.info(multi)
            headers.update({'Content-Length': '{}'.format(len(multi[0]))})
            #_logger.info("params %s",params)
            #_logger.info(headers)
            response = pool.request_encode_body('POST', url+post, params, headers)
            #_logger.info('response: %s , status: %s', response.data,response.status)
            retorno = {'sii_xml_response': response.data, 'sii_result': 'NoEnviado','sii_send_ident':''}
            if response.status != 200:
                return retorno
            respuesta_dict = xmltodict.parse(response.data)
            #_logger.info("l733-dict respuesta")
            #_logger.info(respuesta_dict)
            if respuesta_dict['RECEPCIONDTE']['STATUS'] != '0':
                _logger.info('l736-status no es 0')
                _logger.info(connection_status[respuesta_dict['RECEPCIONDTE']['STATUS']])
            else:
                #_logger.info('l796-status es 0')
                #_logger.info(respuesta_dict['RECEPCIONDTE']['TRACKID'])
                retorno.update({'sii_result': 'Enviado','sii_send_ident':respuesta_dict['RECEPCIONDTE']['TRACKID']})
            return retorno

    '''
    Funcion para descargar el xml en el sistema local del usuario
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    @api.multi
    def get_xml_file(self):
        return {
            'type' : 'ir.actions.act_url',
            'url': '/web/binary/download_document?model=account.invoice\
&field=sii_xml_request&id=%s&filename=demoxml.xml' % (self.id),
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
    Funcion usada en SII para toma de folio desde el archivo de folios (caf)
    Requiere compatibilidad con el addon l10n_cl_dte_caf
    No incluido en dependencias deliberadamente (manejo desde l10n_cl_base)
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def get_caf_file(self, inv):
        # hay que buscar el caf correspondiente al comprobante,
        # trayendolo de la secuencia
        returnvalue = False
        #try:
        if 1==1:
            no_caf = True
            caffiles = inv.journal_document_class_id.sequence_id.dte_caf_ids
            for caffile in caffiles:
                if caffile.status == 'in_use':
                    resultc = base64.b64decode(caffile.caf_file)
                    no_caf = False
                    break
            if no_caf:
                raise Warning(_('''There is no CAF file available or in use \
for this Document. Please enable one.'''))
            resultcaf = xmltodict.parse(resultc.replace(
                '<?xml version="1.0"?>','',1))

            folio_inicial = resultcaf['AUTORIZACION']['CAF']['DA']['RNG']['D']
            folio_final = resultcaf['AUTORIZACION']['CAF']['DA']['RNG']['H']
            folio = self.get_folio(inv)
            if folio not in range(int(folio_inicial), int(folio_final)):
                msg = '''El folio de este documento: {} está fuera de rango \
del CAF vigente (desde {} hasta {}). Solicite un nuevo CAF en el sitio \
www.sii.cl'''.format(folio, folio_inicial, folio_final)
                #_logger.info(msg)
                # defino el status como "spent"
                caffile.status = 'spent'
                raise Warning(_(msg))
            elif folio > int(folio_final) - 2:
                # todo: agregar un wizard al aviso de caf terminándose
                msg = '''El CAF esta pronto a terminarse. Solicite un nuevo \
                CAF para poder continuar emitiendo documentos tributarios'''
            else:
                msg = '''Folio {} OK'''.format(folio)
            #_logger.info(msg)
            returnvalue = resultcaf
        else:
            pass
        return returnvalue

    '''
    Funcion para reformateo del vat desde modo Odoo (dos digitos pais sin guion)
    a valor sin puntuacion con guion
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def format_vat(self, value):
        return value[2:10] + '-' + value[10:]

    '''
    Funcion creacion de imagen pdf417 basada en biblioteca elaphe
     @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
     @version: 2016-05-01
    '''
    def pdf417bc(self, ted):
        #_logger.info('Drawing the TED stamp in PDF417')
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
        #_logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            #_logger.info("""Signature verified! Returning signature, modulus and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64eDigesncode(rsa_m.e)}
        else:
            _logger.info("""Signature verified! Returning signature, modulus, \
exponent. AND DIGEST""")
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
        #_logger.info('Document signature in base64: %s' % FRMT)
        if digst == '':
            #_logger.info("""Signature verified! Returning signature, modulus and exponent.""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e)}
        else:
            #_logger.info("""Signature verified! Returning signature, modulus, \exponent. AND DIGEST""")
            return {
                'firma': FRMT, 'modulus': base64.b64encode(rsa_m.n),
                'exponent': base64.b64encode(rsa_m.e),
                'digest': base64.b64encode(self.digest(MESSAGE))}

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

    @api.multi
    def action_number(self):
        #_logger.info("Entro action_number DTE")
        self.do_dte_send_invoice()
        res = super(invoice, self).action_number()
        return res

    def _acortar_str(self, texto, size=1):
        c = 0
        cadena = ""
        while c < size and c < len(texto):
            cadena += texto[c]
            c += 1
        return cadena

    @api.multi
    def do_dte_send_invoice(self):
        cant_doc_batch = 0
        DTEs = {}
        count = 0
        partners = {}
        clases = {}
        company_id = False
        for rec in self.with_context(lang='es_CL'):
            try:
                signature_d = self.get_digital_signature(rec.company_id)
            except:
                raise Warning(_('''There is no Signer Person with an \
            authorized signature for you in the system. Please make sure that \
            'user_signature_key' module has been installed and enable a digital \
            signature, for you or make the signer to authorize you to use his \
            signature.'''))
            certp = signature_d['cert'].replace(
                BC, '').replace(EC, '').replace('\n', '')
            # control de DTE
            cant_doc_batch = cant_doc_batch + 1
            dte_service = rec.company_id.dte_service_provider
            giros_emisor = []
            for turn in rec.company_id.company_activities_ids:
                giros_emisor.extend([{'Acteco': turn.code}])

            dte = collections.OrderedDict()
            dte1 = collections.OrderedDict()

            dte['Encabezado'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc'] = collections.OrderedDict()
            dte['Encabezado']['IdDoc']['TipoDTE'] = inv.sii_document_class_id.sii_code
            dte['Encabezado']['IdDoc']['Folio'] = folio
            dte['Encabezado']['IdDoc']['FchEmis'] = inv.date_invoice
            # todo: forma de pago y fecha de vencimiento - opcional
            dte['Encabezado']['IdDoc']['FmaPago'] = inv.payment_term_id.dte_sii_code or 1
            dte['Encabezado']['IdDoc']['FchVenc'] = inv.date_due
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
            dte['Encabezado']['Emisor']['DirOrigen'] = inv.company_id.street
            dte['Encabezado']['Emisor']['CmnaOrigen'] = inv.company_id.state_id.name
            dte['Encabezado']['Emisor']['CiudadOrigen'] = inv.company_id.city
            dte['Encabezado']['Receptor'] = collections.OrderedDict()
            dte['Encabezado']['Receptor']['RUTRecep'] = self.format_vat(inv.partner_id.vat)
            dte['Encabezado']['Receptor']['RznSocRecep'] = inv.partner_id.name
            if not inv.invoice_turn:
                raise UserError(_('Seleccione giro del partner'))
            dte['Encabezado']['Receptor']['GiroRecep'] = inv.invoice_turn.name[:40]
            dte['Encabezado']['Receptor']['DirRecep'] = inv.partner_id.street
            dte['Encabezado']['Receptor']['CmnaRecep'] = inv.partner_id.state_id.name
            dte['Encabezado']['Receptor']['CiudadRecep'] = inv.partner_id.city
            dte['Encabezado']['Totales'] = collections.OrderedDict()
            inv = self.env['account.invoice'].search(domain=[('document_number','=', rec.document_number))
            if inv.sii_document_class_id.sii_code == 34 or (inv.sii_referencia_TpoDocRef and inv.sii_referencia_TpoDocRef == '34'):
                dte['Encabezado']['Totales']['MntExe'] = int(round(inv.amount_total, 0))
                if  no_product:
                    dte['Encabezado']['Totales']['MntExe'] = 0
            elif inv.amount_untaxed and inv.amount_untaxed != 0:
                dte['Encabezado']['Totales']['MntNeto'] = int(round(inv.amount_untaxed, 0))
                dte['Encabezado']['Totales']['TasaIVA'] = int(round((inv.amount_total / inv.amount_untaxed -1) * 100, 0))
                dte['Encabezado']['Totales']['IVA'] = int(round(inv.amount_tax, 0))
                if no_product:
                    dte['Encabezado']['Totales']['MntNeto'] = 0
                    dte['Encabezado']['Totales']['TasaIVA'] = 0
                    dte['Encabezado']['Totales']['IVA'] = 0
            monto_total = int(round(inv.amount_total, 0))
            if no_product:
                monto_total = 0
            dte['Encabezado']['Totales']['MntTotal'] = monto_total
            dte['item'] = invoice_lines
            lin_ref = 1
            ref_lines = []
            if dte_service == 'SIIHOMO':
                ref_line = {}
                ref_line = collections.OrderedDict()
                ref_line['NroLinRef'] = lin_ref
                count = count +1
                ref_line['TpoDocRef'] = "SET"
                ref_line['FolioRef'] = folio
                ref_line['FchRef'] = datetime.strftime(datetime.now(), '%Y-%m-%d')
                ref_line['RazonRef'] = "CASO 612122-" + str(inv.sii_batch_number)
                lin_ref = 2
                ref_lines.extend([{'Referencia':ref_line}])
            if inv.sii_referencia_TpoDocRef :
                ref_line = {}
                ref_line = collections.OrderedDict()
                ref_line['NroLinRef'] = lin_ref
                if  inv.sii_referencia_TpoDocRef:
                    ref_line['TpoDocRef'] = inv.sii_referencia_TpoDocRef
                    ref_line['FolioRef'] = inv.origin
                ref_line['FchRef'] = datetime.strftime(datetime.now(), '%Y-%m-%d')
                if inv.sii_referencia_CodRef not in ['','none', False]:
                    ref_line['CodRef'] = inv.sii_referencia_CodRef
                ref_line['RazonRef'] = inv.reference
                ref_lines.extend([{'Referencia':ref_line}])

            dte['refs'] = ref_lines
            doc_id_number = "F{}T{}".format(folio, inv.sii_document_class_id.sii_code)
            # si es sii, inserto el timbre
            if dte_service in ['SII', 'SIIHOMO']:
                # inserto el timbre
                dte['TEDd'] = 'TEDTEDTED'
                # aca completar el XML

            dte1['Documento ID'] = dte
            xml = dicttoxml.dicttoxml(
                dte1, root=False, attr_type=False).replace('<item>','').replace('</item>','').replace('<refs>','').replace('</refs>','')

            # agrego el time en caso que sea para el SII
            if dte_service in ['SII', 'SIIHOMO']:
                xml = xml.replace('<TEDd>TEDTEDTED</TEDd>', ted1)

            root = etree.XML( xml )
            xml_pret = etree.tostring(root, pretty_print=True).replace(
'<EnvioLibro_ID>', doc_id).replace('</EnvioLibro_ID>', '</EnvioLibro>')
            if dte_service in ['SII', 'SIIHOMO']:
                envelope_efact = self.convert_encoding(xml_pret, 'ISO-8859-1')
                envelope_efact = self.create_template_doc(envelope_efact)
                                ## firma del documento
                einvoice = self.sign_full_xml(
                    envelope_efact, signature_d['priv_key'],
                    self.split_cert(certp), doc_id_number)
                #_logger.info('Document signed!')
                if not inv.sii_document_class_id.sii_code in clases:
                    clases[inv.sii_document_class_id.sii_code] = {}
                clases[inv.sii_document_class_id.sii_code].update({inv.id: einvoice})
                partners.update({inv.partner_id.id: clases})
                DTEs.update(partners)
                if not company_id:
                    company_id = inv.company_id
                elif company_id.id != inv.company_id.id:
                    raise UserError("Está combinando compañías")
            company_id = inv.company_id
            if inv.sii_document_class_id.sii_code in [61, 56]:
               inv.state = "paid"
               inv.reconciled = True
        file_name = ""
        dtes={}
        SubTotDTE = ''
        resol_data = self.get_resolution_data(company_id)
        signature_d = self.get_digital_signature(company_id)
        RUTEmisor = self.format_vat(company_id.vat)
        for id_receptor,  receptor in DTEs.iteritems():
            recep = self.env['res.partner'].browse(id_receptor)
            RUTRecep = self.format_vat(recep.vat)
            for id_class_doc, classes in receptor.iteritems():
                NroDte = 0
                for inv_id, documento in classes.iteritems():
                    doc = self.env['account.invoice'].browse(inv_id)
                    dtes.update({str(doc.sii_batch_number): documento})
                    doc.sii_xml_request = documento
                    NroDte += 1
                    file_name += 'F' + str(int(doc.sii_document_number)) + 'T' + str(id_class_doc)
                SubTotDTE += '<SubTotDTE>\n<TpoDTE>' + str(id_class_doc) + '</TpoDTE>\n<NroDTE>'+str(NroDte)+'</NroDTE>\n</SubTotDTE>\n'
        documentos =""
        for key in sorted(dtes.iterkeys()):
            documentos += '\n'+dtes[key]
        # firma del sobre
        RUTRecep = "60803000-K" # RUT SII
        dtes = self.create_template_envio( RUTEmisor, RUTRecep,
            resol_data['dte_resolution_date'],
            resol_data['dte_resolution_number'],
            self.convert_timezone(
            datetime.strftime(datetime.now(), '%Y-%m-%d'),
            datetime.strftime(
            datetime.now(), '%H:%M:%S')).strftime(
                '%Y-%m-%dT%H:%M:%S'), documentos, signature_d,SubTotDTE )
        envio_dte  = self.create_template_env(dtes)
        envio_dte = self.sign_full_xml(
            envio_dte, signature_d['priv_key'], certp,
            'SetDoc', 'env')
        self.xml_validator(envio_dte, 'libro')
        result = self.send_xml_file(envio_dte, file_name, company_id)
        for inv in self:
            inv.write({'sii_xml_response':result['sii_xml_response'], 'sii_send_ident':result['sii_send_ident'], 'sii_result': result['sii_result']})
            last = inv
        last.write(result)


    def _get_send_status(self, track_id, signature_d,token):
        url = server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws?WSDL'
        ns = 'urn:'+ server_url[self.company_id.dte_service_provider] + 'QueryEstUp.jws'
        _server = SOAPProxy(url, ns)
        respuesta = _server.getEstUp(signature_d['subject_serial_number'][:8],signature_d['subject_serial_number'][-1],track_id,token)
        self.sii_message = respuesta
        resp = xmltodict.parse(respuesta)
        #_logger.info(resp)
        status = False
        if resp['SII:RESPUESTA']['SII:RESP_HDR']['ESTADO'] == "-11":
            status =  {'warning':{'title':_('Error -11'), 'message': _("Error -11: Espere a que sea aceptado por el SII, intente en 5s más")}}
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
        respuesta = _server.getEstDte(signature_d['subject_serial_number'][:8], str(signature_d['subject_serial_number'][-1]),
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

    @api.multi
    def getResumen(self, inv):
        no_product = False
        det = collections.OrderedDict()
        det['TpoDoc'] = inv.sii_document_class_id.sii_code
        det['NroDoc'] = int(inv.number)
        if inv.sii_document_class_id.sii_code == 34 or (inv.sii_referencia_TpoDocRef and inv.sii_referencia_TpoDocRef == '34'):
            det['TasaImp'] = 0
        det['FchDoc'] = inv.date_invoice
        if 1==2:#@TODO Sucursales
            det['CdgSIISucur']=False
        det['RUTDoc'] = self.format_vat(inv.partner_id.vat)
        det['RznSoc'] = inv.partner_id.name
        if inv.sii_document_class_id.sii_code == 34 or (inv.sii_referencia_TpoDocRef and inv.sii_referencia_TpoDocRef == '34'):
            det['Detalles']['MntExe'] = int(round(inv.amount_total, 0))
            if  no_product:
                de['Detalles']['MntExe'] = 0
        elif inv.amount_untaxed and inv.amount_untaxed != 0:
            det['TasaImp'] = int(round((inv.amount_total / inv.amount_untaxed -1) * 100, 0))
            det['MntNeto'] = int(round(inv.amount_untaxed, 0))
            det['MntIVA'] = int(round(inv.amount_tax, 0))
            if no_product:
                det['MntNeto'] = 0
                det['MntIVA'] = 0
        monto_total = int(round(inv.amount_total, 0))
        if no_product:
            monto_total = 0
        det['Detalles']['MntTotal'] = monto_total
        return det

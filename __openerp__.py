# -*- coding: utf-8 -*-
{
    "name": """Chile - Web Services de Documentos Tributarios Electrónicos\
    """,
    'version': '9.0.4.0.0',
    'category': 'Localization/Chile',
    'sequence': 12,
    'author':  'BMyA SA - Blanco Martín & Asociados, Daniel Santibáñez Polanco',
    'website': 'http://blancomartin.cl',
    'license': 'AGPL-3',
    'summary': '',
    'description': """
Chile: API and GUI to access Electronic Invoicing webservices.
""",
    'depends': [
        'webservices_generic',
        'l10n_cl_counties',
        'l10n_cl_invoice',
        'l10n_cl_dte_caf',
        'account',
        'report',
        'purchase',
        ],
    'external_dependencies': {
        'python': [
            'xmltodict',
            'dicttoxml',
            'elaphe',
            'M2Crypto',
            'base64',
            'hashlib',
            'cchardet',
            'suds',
            'urllib3',
            'SOAPpy',
            'signxml',
            'ast'
        ]
    },
    'data': [
        'views/invoice_view.xml',
        'views/partner_view.xml',
        'views/company_view.xml',
        'views/payment_t_view.xml',
        'views/sii_regional_offices_view.xml',
        'views/layout.xml',
        'views/sii_cola_envio.xml',
        'wizard/masive_send_dte.xml',
        'wizard/upload_xml.xml',
        'wizard/validar.xml',
        'data/sii.regional.offices.csv',
        'data/sequence.xml',
        'data/cron.xml',
        'security/ir.model.access.csv',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
}

import lxml.etree as ET
import datetime
import os
import hashlib
import zlib
from copy import deepcopy
from io import BytesIO
from flask import Flask, request, Response
from base64 import b16encode, b64encode, b64decode, encodebytes
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
                                                          Encoding)

PROVIDER = "Randori Test IdP"
DECOMPRESS = False
HOST = "localhost"
PORT = 10443

IDP_ROOT = f"https://{HOST}:{PORT}"
CERT_FILE = 'cert.pem'  # used for SSL and signing
KEY_FILE = 'key-plain.pem'
CERT = open(CERT_FILE).read()
KEY = open(KEY_FILE).read()
private_key = load_pem_private_key(KEY.encode(), None)
DER_CERT = encodebytes(
    x509.load_pem_x509_certificate(CERT.encode()).public_bytes(Encoding.DER)
).strip()

xml = b'<?xml version="1.0" encoding="UTF-8"?>'
s = 'http://www.w3.org/2003/05/soap-envelope'
xs = 'http://www.w3.org/2001/XMLSchema'
a = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
md = 'urn:oasis:names:tc:SAML:2.0:metadata'
samlp = 'urn:oasis:names:tc:SAML:2.0:protocol'
saml2 = 'urn:oasis:names:tc:SAML:2.0:assertion'
ds = 'http://www.w3.org/2000/09/xmldsig#'
nameid_email = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
nameid_entity = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
status_success = 'urn:oasis:names:tc:SAML:2.0:status:Success'
binding_post = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
binding_redirect = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
cm_bearer = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
class_ppt = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
exc_c14n = 'http://www.w3.org/2001/10/xml-exc-c14n#'
rsa_sha256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
enveloped_signature = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
sha256_digest = 'http://www.w3.org/2001/04/xmlenc#sha256'

ns = {'s': s,
      'xs': xs,
      'a': a,
      'md': md,
      'samlp': samlp,
      'saml2': saml2,
      'ds': ds}


def tsnow(delta_seconds=0):
    return (datetime.datetime.utcnow() + datetime.timedelta(
        seconds=delta_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def make_id():
    return '_'+b16encode(os.urandom(10)).decode()


def element(tag, **kwargs):
    ns_name, tag_name = tag.split(':')
    return ET.Element('{%s}%s' % (ns[ns_name], tag_name),
                      nsmap={ns_name: ns[ns_name]}, **kwargs)


def subelement(parent, tag, **kwargs):
    ns_name, tag_name = tag.split(':')
    return ET.SubElement(parent, '{%s}%s' % (ns[ns_name], tag_name),
                         nsmap={ns_name: ns[ns_name]}, **kwargs)


def get_metadata():
    ed = element('md:EntityDescriptor', attrib={'entityID': IDP_ROOT})
    desc = subelement(ed, 'md:IDPSSODescriptor',
                      attrib={'WantAuthnRequestsSigned': 'false',
                              'protocolSupportEnumeration': samlp})
    kd = subelement(desc, 'md:KeyDescriptor', attrib={'Use': 'signing'})
    ki = subelement(kd, 'ds:KeyInfo')
    x509data = subelement(ki, 'ds:X509Data')
    x509cert = subelement(x509data, 'ds:X509Certificate')
    x509cert.text = DER_CERT
    subelement(desc, 'md:NameIDFormat').text = nameid_email
    subelement(desc, 'md:SingleSignOnService',
               attrib={'Binding': binding_post,
                       'Location': IDP_ROOT})
    subelement(desc, 'md:SingleSignOnService',
               attrib={'Binding': binding_redirect,
                       'Location': IDP_ROOT})
    return ed


def sign(el_to_sign):
    el_to_sign = deepcopy(el_to_sign)
    ET.cleanup_namespaces(el_to_sign)
    digest = b64encode(hashlib.sha256(c14n(el_to_sign)).digest()).decode()
    signature = element('ds:Signature')
    signed_info = subelement(signature, 'ds:SignedInfo')
    subelement(signed_info, 'ds:CanonicalizationMethod',
               attrib={'Algorithm': exc_c14n})
    subelement(signed_info, 'ds:SignatureMethod',
               attrib={'Algorithm': rsa_sha256})
    ref = subelement(signed_info, 'ds:Reference',
                     attrib={'URI': '#'+el_to_sign.attrib['ID']})
    tr = subelement(ref, 'ds:Transforms')
    subelement(tr, 'ds:Transform',
               attrib={'Algorithm': enveloped_signature})
    subelement(tr, 'ds:Transform',
               attrib={'Algorithm': exc_c14n})
    subelement(ref, 'ds:DigestMethod',
               attrib={'Algorithm': sha256_digest})
    subelement(ref, 'ds:DigestValue').text = digest
    ET.cleanup_namespaces(signature)
    sig_data = c14n(signed_info)
    print(sig_data)
    sig = private_key.sign(sig_data, padding.PKCS1v15(), hashes.SHA256())
    sig = b64encode(sig).decode()
    subelement(signature, 'ds:SignatureValue').text = sig
    ki = subelement(signature, 'ds:KeyInfo')
    x5d = subelement(ki, 'ds:X509Data')
    x5c = subelement(x5d, 'ds:X509Certificate')
    x5c.text = DER_CERT
    ET.cleanup_namespaces(signature)
    return signature


def make_assertion(resp, acs, irt, iss, username, validity):
    assertion = subelement(resp, 'saml2:Assertion',
                           attrib={'ID': make_id(),
                                   'IssueInstant': tsnow(),
                                   'Version': '2.0'})
    issuer = subelement(assertion, 'saml2:Issuer',
                        attrib={'Format': nameid_entity})
    issuer.text = IDP_ROOT
    subject = subelement(assertion, 'saml2:Subject')
    subelement(subject, 'saml2:NameID',
               attrib={'Format': nameid_email}).text = username
    cm = subelement(subject, 'saml2:SubjectConfirmation',
                    attrib={'Method': cm_bearer})
    subelement(cm, 'saml2:SubjectConfirmationData',
               attrib={'InResponseTo': irt,
                       'NotOnOrAfter': tsnow(validity),
                       'Recipient': acs})
    cond = subelement(assertion, 'saml2:Conditions',
                      attrib={'NotBefore': tsnow(-validity),
                              'NotOnOrAfter': tsnow(validity)})
    aud_rest = subelement(cond, 'saml2:AudienceRestriction')
    subelement(aud_rest, 'saml2:Audience').text = acs  # todo urlparse
    authn = subelement(assertion, 'saml2:AuthnStatement',
                       attrib={'AuthnInstant': iss,
                               'SessionIndex': irt})
    authn_ctx = subelement(authn, 'saml2:AuthnContext')
    subelement(authn_ctx, 'saml2:AuthnContextClassRef').text = class_ppt
    return assertion, issuer  # sig must be placed after issuer (xsl doc)


def make_response(acs, irt, iss, username,
                  sign_assertion=True,
                  sign_response=False,
                  validity=300):
    resp = element('samlp:Response',
                   attrib={'Destination': acs, 'ID': make_id(),
                           'InResponseTo': irt, 'IssueInstant': tsnow(),
                           'Version': '2.0'})
    issuer = subelement(resp, 'saml2:Issuer',
                        attrib={'Format': nameid_entity})
    issuer.text = IDP_ROOT
    status = subelement(resp, 'samlp:Status')
    subelement(status, 'samlp:StatusCode',
               attrib={'Value': status_success})
    assertion, as_issuer = make_assertion(resp, acs, irt, iss, username,
                                          validity)

    ET.cleanup_namespaces(resp)
    if sign_assertion:
        as_issuer.addnext(sign(assertion))
    if sign_response:
        issuer.addnext(sign(resp))
    return resp


def c14n(element):
    out = BytesIO()
    ET.ElementTree(element).write_c14n(out)
    return out.getvalue()


def one(element):
    assert len(element) == 1, len(element)
    return element[0]


def parse_req(reqstr):
    if DECOMPRESS is True:
        reqstr = zlib.decompress(reqstr, -zlib.MAX_WBITS)
    print(reqstr)
    req = ET.XML(reqstr)
    return req.attrib


app = Flask(__name__)


@app.route("/metadata")
def metadata():
    out = xml+c14n(get_metadata())
    return Response(out, mimetype='text/xml')


@app.route("/", methods=['POST', 'GET'])
def root():
    try:
        attrib = parse_req(b64decode(request.values.get('SAMLRequest')))
    except Exception as e:
        print(f'Unable to parse SAML request {e}')
        return 'SAMLRequest was not understood by this ACS endpoint', 400
    acs = attrib['AssertionConsumerServiceURL']
    id_ = attrib['ID']
    iss = attrib['IssueInstant']
    relay_state = request.values.get('RelayState')
    return f'''<HTML><BODY><CENTER><H1>Login - Step 1</H1>
<FORM ACTION="https://{HOST}:{PORT}/login" METHOD=POST>
Username: <INPUT TYPE=TEXT VALUE="admin" NAME="username"><BR>
InResponseTo: <INPUT TYPE=TEXT VALUE="{id_}" NAME="irt"><BR>
IssueInstant: <INPUT TYPE=TEXT VALUE="{iss}" NAME="iss"><BR>
ACS: <INPUT TYPE=TEXT VALUE="{acs}" NAME="acs"><BR>
RelayState: <INPUT TYPE=TEXT VALUE="{relay_state}" NAME="RelayState"><BR>
Sign Assertion (Required): <INPUT TYPE=CHECKBOX NAME="sa" CHECKED><BR>
Sign Response: <INPUT TYPE=CHECKBOX NAME="sr" CHECKED><BR>
Validity +/-: <INPUT TYPE=TEXT NAME="valid" VALUE=3600> sec<BR>
<INPUT TYPE=SUBMIT VALUE="Submit"></FORM></BODY></HTML>'''


@app.route("/login", methods=['POST'])
def login():
    acs = request.values.get('acs')
    irt = request.values.get('irt')
    iss = request.values.get('iss')
    print(request.values.get('sa'))
    relay_state = request.values.get('RelayState')
    username = request.values.get('username')
    response_xml = c14n(make_response(
        acs, irt, iss, username,
        validity=int(request.values.get('valid')),
        sign_assertion=request.values.get('sa'),
        sign_response=request.values.get('sr')))
    response = b64encode(response_xml).decode()
    return f'''<HTML><BODY><CENTER><H1>Login - Step 2</H1>
<TEXTAREA>{response_xml.decode()}</TEXTAREA>
<FORM ACTION="{acs}" METHOD=POST>
SAMLResponse: <TEXTAREA NAME="SAMLResponse">{response}</TEXTAREA><BR>
RelayState: <INPUT TYPE=TEXT VALUE="{relay_state}" NAME="RelayState"><BR>
<INPUT TYPE=SUBMIT VALUE="Submit"></FORM></BODY></HTML>'''


if __name__ == "__main__":
    app.run(ssl_context=(CERT_FILE, KEY_FILE),
            port=PORT, host='0.0.0.0')

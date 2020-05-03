#!/bin/sh
''''[ -z $LOG ] && export LOG=/dev/stdout # '''
''''which python  >/dev/null && exec python  -u "$0" "$@" >> $LOG 2>&1 # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# Copyright (C) 2018 LinuxServer.io
# Copyright (C) 2020 Philipp Staiger

import sys, signal, ldap, argparse
from http.cookies import BaseCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from cryptography.fernet import Fernet, InvalidToken

class AuthHandler(BaseHTTPRequestHandler):

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):

        ctx = self.ctx

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie is None:
            self.auth_failed(ctx, 'AuthZ empty or invalid format: %s' % auth_cookie)
            return True

        ctx['action'] = 'decoding credentials'

        try:
            cipher_suite = Fernet(REPLACEWITHFERNETKEY)
            auth_decoded = auth_cookie.encode("utf-8")
            auth_decoded = cipher_suite.decrypt(auth_decoded)
            auth_decoded = auth_decoded.decode("utf-8")
            user, mfa, passwd = auth_decoded.split(':', 2)
        except InvalidToken:
            self.auth_failed(ctx, 'Incorrect token.')
            return True
        except Exception as e:
            self.auth_failed(ctx)
            self.log_error(e)
            return True

        ctx['user'] = user
        ctx['pass'] = passwd

        if ctx['mfa'] and ctx['mfa'] != mfa:
            self.auth_failed(ctx, 'MFA method does not match!')
            return True


        # Continue request processing
        return False

    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            authcookie = BaseCookie(cookies).get(name)
            if authcookie:
                return authcookie.value
            else:
                return None
        else:
            return None


    # Log the error and complete the request with appropriate status
    def auth_failed(self, ctx, errmsg = None):

        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(401)
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            user = self.ctx['user']

        sys.stdout.write("%s [auth-daemon] %s [%s] %s\n" % (addr, user,
                         self.log_date_time_string(), format % args))
        sys.stdout.flush()

    def log_error(self, format, *args):
        self.log_message(format, *args)


# Verify username/password against LDAP server
class LDAPAuthHandler(AuthHandler):
    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
             # parameter      header         default
             'url': ('X-Ldap-URL', None),
             'starttls': ('X-Ldap-Starttls', 'false'),
             'basedn': ('X-Ldap-BaseDN', None),
             'template': ('X-Ldap-Template', '(cn=%(username)s)'),
             'binddn': ('X-Ldap-BindDN', ''),
             'bindpasswd': ('X-Ldap-BindPass', ''),
             'cookiename': ('X-Cookie-Name', 'nginxauth'),
             'headername': ('X-Header-Name', ''),
             'mfa': ('X-MFA', '')
        }

    @classmethod
    def set_params(cls, params):
        cls.params = params

    def get_params(self):
        return self.params

    # GET handler for the authentication request
    def do_GET(self):

        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        if AuthHandler.do_GET(self):
            # request already processed
            return

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return

        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            ldap_obj = ldap.initialize(ctx['url']);

            # Python-ldap module documentation advises to always
            # explicitely set the LDAP version to use after running
            # initialize() and recommends using LDAPv3. (LDAPv2 is
            # deprecated since 2003 as per RFC3494)
            #
            # Also, the STARTTLS extension requires the
            # use of LDAPv3 (RFC2830).
            ldap_obj.protocol_version=ldap.VERSION3

            # Establish a STARTTLS connection if required by the
            # headers.
            if ctx['starttls'] == 'true':
                ldap_obj.start_tls_s()

            # See http://www.python-ldap.org/faq.shtml
            # uncomment, if required
            # ldap_obj.set_option(ldap.OPT_REFERRALS, 0)

            ctx['action'] = 'binding as search user'
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % { 'username': ctx['user'] }

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                              (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE,
                                          searchfilter, ['objectclass'], 1)

            ctx['action'] = 'verifying search query results'
            if len(results) < 1:
                self.auth_failed(ctx, 'no objects found')
                return

            ctx['action'] = 'binding as an existing user'
            ldap_dn = results[0][0]
            ctx['action'] += ' "%s"' % ldap_dn
            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('Auth OK for user "%s"' % (ctx['user']))

            # Successfully authenticated user
            self.send_response(200)
            if ctx['headername'] != None and ctx['headername'] != '':
                self.send_header(ctx['headername'], ctx['user'])
            self.end_headers()

        except Exception as e:
            self.auth_failed(ctx)
            self.log_error(str(e))
            raise

def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""Simple Nginx LDAP authentication helper.""")
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('--host',  metavar="hostname",
        default="localhost", help="host to bind (Default: localhost)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        default=8888, help="port to bind (Default: 8888)")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
        default="ldap://localhost:389",
        help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-s', '--starttls', metavar="starttls",
        default="false",
        help=("Establish a STARTTLS protected session (Default: false)"))
    group.add_argument('-b', metavar="baseDn", dest="basedn", default='',
        help="LDAP base dn (Default: unset)")
    group.add_argument('-D', metavar="bindDn", dest="binddn", default='',
        help="LDAP bind DN (Default: anonymous)")
    group.add_argument('-w', metavar="passwd", dest="bindpw", default='',
        help="LDAP password for the bind DN (Default: unset)")
    group.add_argument('-f', '--filter', metavar='filter',
        default='(cn=%(username)s)',
        help="LDAP filter (Default: cn=%%(username)s)")
    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-c', '--cookie', metavar="cookiename",
        default="nginxauth", help="HTTP cookie name to set in (Default: nginxauth)")
    group.add_argument('-H', '--headername', metavar="headername",
        default="", help="HTTP header name to return username (Default: unset)")
    group.add_argument('-M', '--mfa', metavar="mfa",
        default="", help="MFA header name to return mfa method (Default: unset)")

    args = parser.parse_args()
    global Listen
    Listen = (args.host, args.port)
    auth_params = {
             'url': ('X-Ldap-URL', args.url),
             'starttls': ('X-Ldap-Starttls', args.starttls),
             'basedn': ('X-Ldap-BaseDN', args.basedn),
             'template': ('X-Ldap-Template', args.filter),
             'binddn': ('X-Ldap-BindDN', args.binddn),
             'bindpasswd': ('X-Ldap-BindPass', args.bindpw),
             'cookiename': ('X-Cookie-Name', args.cookie),
             'headername': ('X-Header-Name', args.headername),
             'mfa': ('X-MFA', args.mfa)
    }
    LDAPAuthHandler.set_params(auth_params)
    server = ThreadingHTTPServer(Listen, LDAPAuthHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    sys.stdout.write("[auth-daemon] Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()
    server.serve_forever()
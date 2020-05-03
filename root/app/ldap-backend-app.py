#!/bin/sh
''''[ -z $LOG ] && export LOG=/dev/stdout # '''
''''which python  >/dev/null && exec python  -u "$0" "$@" >> $LOG 2>&1 # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# Copyright (C) 2018 LinuxServer.io
# Copyright (C) 2020 Philipp Staiger

import sys, signal, cgi, ldap, argparse

import duo_web
from http.cookies import BaseCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

cipher_suite = Fernet(REPLACEWITHFERNETKEY)

# Implement Login Frontend
class AppAuthHandler(BaseHTTPRequestHandler):
    
    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
             # parameter      header         default
             'url': ('X-Ldap-URL', None),
             'starttls': ('X-Ldap-Starttls', 'false'),
             'basedn': ('X-Ldap-BaseDN', None),
             'template': ('X-Ldap-Template', '(cn=%(username)s)'),
             'binddn': ('X-Ldap-BindDN', ''),
             'bindpasswd': ('X-Ldap-BindPass', ''),
             'cookiename': ('X-Cookie-Name', None),
             'cookiedomain': ('X-Cookie-Domain', ''),
             'headername': ('X-Header-Name', ''),
             'mfa': ('X-MFA', ''),
             'target': ('X-Target', None),
             'basepath': ('X-Path', ''),
             'loginpath': ('X-Path-Login', '/login'),
             'logoutpath': ('X-Path-Logout', '/logout'),
             'logourl': ('X-Url-Logo', ''),
             'redirecturl': ('X-Url-Redirect', ''),
             'duoikey': ('X-Duo-ikey', ''),
             'duoskey': ('X-Duo-skey', ''),
             'duoakey': ('X-Duo-akey', ''),
             'duohost': ('X-Duo-host', ''),
        }

    @classmethod
    def set_params(cls, params):
        cls.params.update(params)

    def get_params(self):
        return self.params

    def init_ctx(self):
        
        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing auth handler'
        ctx['user'] = '-'

        ctx['action'] = 'input parameters check'
        for k, v in self.params.items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] is None:
                self.log_error('required "%s" header was not passed' % k)
                self.auth_form('required "%s" header was not passed' % k, target = '/')
        
        ctx['path'] = urlparse(self.path).path


    # GET handler for the authentication request
    def do_GET(self):

        self.init_ctx()
        ctx = self.ctx

        ctx['action'] = 'selecting action'

        if ctx['path'].startswith(ctx['basepath']+ctx['loginpath']):
            return self.auth_form()
        elif ctx['path'].startswith(ctx['basepath']+ctx['logoutpath']):
            return self.logout()
        else:
            self.log_error("Invalid Path: %s" % ctx['path'])
            return self.auth_form("An error occurred - Please check with your administrator!")

    # send logout message html and redirect to specified logout url
    def logout(self):
        
        ctx = self.ctx

        logo_part = ''
        if ctx['logourl']:
            logo_part = '<img class="logo" src="' + ctx['logourl'] + '">'

        cookie_domain_part = ''
        if ctx['cookiedomain']:
            cookie_domain_part = 'domain=' + ctx['cookiedomain'] + ';'

        logout_redirect_part = ''
        if ctx['redirecturl']:
            logout_redirect_part = '<meta http-equiv="refresh" content="3;url=' + ctx['redirecturl'] + '" />'

        if self.get_id(self.get_cookie(ctx['cookiename'])):
            user_part = "You are now logged out"
        else:
            user_part = "Hey " + ctx['user'] + ", you are now logged out"

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
    <head>
        <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
        {redirect}
        <title>Log Out</title>
        <style type="text/css" rel="stylesheet">
            body {{ background-color: #f1f1f1; font-family: sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }}
            .log-in {{ width: 400px; max-height: 550px; position: absolute; top: 0; bottom: 0; left: 0; right: 0; margin: auto; background-color: #fff; border-radius: 3px; overflow: hidden; -webkit-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); -moz-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); }}
            .log-in > div {{ position: relative; }}
            .log-in .content {{ margin-top: 50px; padding: 20px; text-align: center; }}
			.logo {{ text-align: center; max-height: 150px; }}
            h1, h2 {{ text-align: center; }}
            h1 {{ margin-top: 20px; margin-bottom: 20px; letter-spacing: -0.05rem; color: #565656; font-size: 1.6rem; }}
        </style>
    </head>
    <body>
        <div class="log-in">
            <div class="content">
				{logo}
                <h1>{message}</h1>
            </div>
        </div>
    </body>
</html>"""
        self.send_response(200)
        # Proxy Auth
        self.send_header('Set-Cookie', ctx['cookiename'] + '=deleted; Max-Age=0; ' + cookie_domain_part + ' Path=/; HttpOnly')
        self.end_headers()
        self.write_response(html.format(redirect = logout_redirect_part, logo = logo_part, message = user_part))


    # send login form html
    def auth_form(self, message = None, target = None):
        
        ctx = self.ctx

        if target:
            ctx['target'] = target

        logo_part = ''
        if ctx['logourl']:
            logo_part = '<img class="logo" src="' + ctx['logourl'] + '">'

        msg_part = ''
        if message:
            msg_part = '<h2>%s</h2>' % message

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
    <head>
        <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
        <title>Log In</title>
        <style type="text/css" rel="stylesheet">
            body {{ background-color: #f1f1f1; font-family: sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }}
            .log-in {{ width: 400px; max-height: 550px; position: absolute; top: 0; bottom: 0; left: 0; right: 0; margin: auto; background-color: #fff; border-radius: 3px; overflow: hidden; -webkit-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); -moz-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); }}
            .log-in > div {{ position: relative; }}
            .log-in .content {{ padding: 20px; text-align: center; }}
			.logo {{ text-align: center; max-height: 150px; }}
            h1, h2 {{ text-align: center; }}
            h1 {{ margin-top: 20px; margin-bottom: 20px; letter-spacing: -0.05rem; color: #565656; font-size: 1.6rem; }}
            h1 {{ margin: 0px;letter-spacing: -0.05rem; color: #888; font-size: 1.2rem; }}
            form {{ margin-top: 50px; }}
            input[type="text"], input[type="password"] {{ width: 80%; padding: 10px; border-top: 0; border-left: 0; border-right: 0; outline: none; }}
            input[type="text"]:focus, input[type="password"]:focus {{ border-bottom: 2px solid #666; }}
            button {{ width: 80%; padding: 10px; background-color: #3468e2; border: none; color: #fff; cursor: pointer; margin-top: 50px; }}
            button:hover {{ background-color: #5581e8; }}
        </style>
    </head>
    <body>
        <div class="log-in">
            <div class="content">
                {logo}
                <h1>Log in to your account</h1>
                {message}
                <form action="{action}" method="post">
                    <p>
                        <input type="text" name="username" placeholder="Username" aria-label="Username" />
                    </p>
                    <p>
                        <input type="password" name="password" placeholder="Password" aria-label="Password" />
                    </p>
                    <input type="hidden" name="target" value="{target}">
                    <button type="submit" class="submit btn btn-primary">Log In</button>
                </form>
            </div>
        </div>
    </body>
</html>"""

        self.send_response(200)
        self.end_headers()
        self.write_response(html.format(action = ctx['basepath']+ctx['loginpath'], logo = logo_part, target = ctx['target'], message = msg_part))


    # send login form html
    def duo_form(self, cookie):
        
        ctx = self.ctx

        logo_part = ''
        if ctx['logourl']:
            logo_part = '<img class="logo" src="' + ctx['logourl'] + '">'

        sig_request = duo_web.sign_request(ctx['duoikey'], ctx['duoskey'], ctx['duoakey'], ctx['user'])

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
    <head>
        <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
        <title>Log In Duo</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <style type="text/css" rel="stylesheet">
            body {{ background-color: #f1f1f1; font-family: sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }}
            .log-in {{ width: 400px; max-height: 590px; position: absolute; top: 0; bottom: 0; left: 0; right: 0; margin: auto; background-color: #fff; border-radius: 3px; overflow: hidden; -webkit-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); -moz-box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); box-shadow: 0px 0px 2px 0px rgba(222,222,222,1); }}
            .log-in > div {{ position: relative; }}
            .log-in .content {{ padding: 20px; text-align: center; }}
			.logo {{ text-align: center; max-height: 150px; }}
            h1, h2 {{ text-align: center; }}
            h1 {{ margin-top: 20px; margin-bottom: 20px; letter-spacing: -0.05rem; color: #565656; font-size: 1.6rem; }}
            iframe {{ width: 100%; min-width: 304px; max-width: 620px; height: 330px; }}
        </style>
    </head>
    <body>
        <div class="log-in">
            <div class="content">
                {logo}
                <h1>Duo Authentication Prompt</h1>
                <script src='https://api.duosecurity.com/frame/hosted/Duo-Web-v2.min.js'></script>

                <iframe id="duo_iframe"
                        title="Two-Factor Authentication"
                        frameborder="0"
                        data-host="{host}"
                        data-sig-request="{sig_request}"
                        >
                </iframe>
                <form method="POST" id="duo_form">
                    <input type="hidden" name="target" value="{target}">
                </form>
            </div>
        </div>
    </body>
</html>"""

        self.send_response(200)
        self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.write_response(html.format(host = ctx['duohost'], sig_request = sig_request, logo = logo_part, target = ctx['target']))


    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        self.init_ctx()
        ctx = self.ctx

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, headers = self.headers,
                                environ = env)
        ctx['target'] = form.getvalue('target')
        ctx['user'] = form.getvalue('username')
        ctx['pass'] = form.getvalue('password')
        
        if not ctx['path'].startswith(ctx['basepath']+ctx['loginpath']):
            log_error("Invalid Path: %s" % ctx['path'])
            return self.auth_form("An error occurred - Please check with your administrator!")

        # DUO auth
        if (sig_response := form.getvalue('sig_response')) and ctx['mfa'] == "duo":
            
            username = duo_web.verify_response(ctx['duoikey'], ctx['duoskey'], ctx['duoakey'], sig_response)

            if username is None:
                # See if it was a response to an ENROLL_REQUEST
                username = duo_web.verify_enroll_response(
                    ctx['duoikey'], ctx['duoskey'], ctx['duoakey'], sig_response)

                if username is None:
                    return self.auth_form('Duo authentication failed')
                else:
                    return self.auth_form('Enrolled with Duo as %s.' % username)

            else:
                if error := self.get_id(self.get_cookie(ctx['cookiename'])):
                    self.log_error(error)
                    return self.auth_form('An error occurred - please try again!')

                if username != ctx['user']:
                    return self.auth_form("Users don't match! MFA:%s - Form: %s" % (username, ctx['user']))

        # Auth

        if ctx['user'] and ctx['pass'] and ctx['target']:

            try:
                if error := self.ldap_auth():
                    self.log_error(error)
                    return self.auth_form('Authentication failed')
            except Exception as e:
                self.log_error(str(e))
                return self.auth_form('Authentication failed')

            if ctx['mfa'] == "duo" and not sig_response: # Duo mfa required
                cookie = self.set_cookie(ctx['user'], ctx['pass'], None)
                return self.duo_form(cookie)

            if not ctx['mfa'] or ctx['mfa'] == "duo": # Auth successfull without mfa or with duo
                cookie = self.set_cookie(ctx['user'], ctx['pass'], ctx['mfa'])
                self.send_response(302)
                self.send_header('Location', ctx['target'])
                self.send_header('Set-Cookie', cookie)
                self.end_headers()
                return

        return self.auth_form('Authentication failed')


    # Encodes response and writes it out to response
    def write_response(self, response):
        self.wfile.write(response.encode("utf-8"))

    def set_cookie(self, user, password, mfa = None):

        ctx = self.ctx

        if not mfa:
            mfa = ''

        enc = user + ':' + mfa + ':' + password
        enc = cipher_suite.encrypt(enc.encode("utf-8"))
        enc = enc.decode()

        cookie_domain_part = ''
        if ctx['cookiedomain']:
            cookie_domain_part = 'Domain=' + ctx['cookiedomain'] + ';'

        return ctx['cookiename'] + '=' + enc + '; ' + cookie_domain_part + ' Path=/; HttpOnly' # ; Secure # Max-Age:XXXs

    def ldap_auth(self):

        ctx = self.ctx

        # check that uri and baseDn are set
        # either from cli or a request
        if not ctx['url']:
            return 'LDAP URL is not set!'
        if not ctx['basedn']:
            return 'LDAP baseDN is not set!'

        ctx['action'] = 'initializing LDAP connection'
        ldap_obj = ldap.initialize(ctx['url'])

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
            return 'no objects found'

        ctx['action'] = 'binding as an existing user'
        ldap_dn = results[0][0]
        ctx['action'] += ' "%s"' % ldap_dn
        ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

        self.log_message('Auth OK for user "%s"' % (ctx['user']))

    # Return Error Message if failed, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def get_id(self, auth_cookie):
        
        ctx = self.ctx

        ctx['action'] = 'performing authorization'

        if auth_cookie is None:
            return 'Primary auth was not completed before MFA!'

        ctx['action'] = 'decoding credentials'

        try:
            auth_decoded = auth_cookie.encode("utf-8")
            auth_decoded = cipher_suite.decrypt(auth_decoded)
            auth_decoded = auth_decoded.decode("utf-8")
            user, mfa, passwd = auth_decoded.split(':', 2)
        except InvalidToken:
            return 'Incorrect token.'
        except Exception:
            return 'Exception decoding'

        ctx['user'] = user
        ctx['pass'] = passwd

        # Continue request processing
        return
    
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

        sys.stdout.write("%s [auth-app] %s [%s] %s\n" % (addr, user,
                         self.log_date_time_string(), format % args))
        sys.stdout.flush()

    def log_error(self, format, *args):

        if not hasattr(self, 'ctx'):
            msg = 'Error'
        else:
            msg = 'Error while ' + self.ctx['action']

        if format:
            msg += ': ' + format

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        self.log_message(msg, *args)
    
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
        default=9000, help="port to bind (Default: 9000)")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-u', '--url', metavar="URL",
        default="ldap://localhost:389",
        help=("LDAP URI to query (Default: ldap://localhost:389)"))
    group.add_argument('-s', '--starttls', action='store_true', default="false",
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
    group.add_argument('-P', '--basepath', metavar="path",
        default="", help="HTTP base path for all requests (Default: unset)")
    group.add_argument('--loginpath', metavar="path",
        default="/login", help="HTTP path for login app (Default: /login)")
    group.add_argument('--logoutpath', metavar="path",
        default="/logout", help="HTTP path for logout app (Default: /logout)")
    group.add_argument('-c', '--cookiename', metavar="name",
        default="nginxauth", help="HTTP cookie name to set in (Default: nginxauth)")
    group.add_argument('-C', '--cookiedomain', metavar="domain",
        default="", help="HTTP cookie name to set in (Default: unset)")
    group.add_argument('-H', '--headername', metavar="name",
        default="", help="HTTP header name to return username (Default: unset)")
    group.add_argument('-M', '--mfa', metavar="method",
        default="", help="MFA header name to return mfa method (Default: unset)")
    # App options:
    group = parser.add_argument_group(title="App options")
    group.add_argument('--logo', metavar="url",
        default="", help="App Logo Url to be displayed (Default: unset)")
    group.add_argument('--logoutredirect', metavar="url",
        default="", help="Url to be redirected after Logout (Default: unset)")
    # Duo options:
    group = parser.add_argument_group(title="Duo options")
    group.add_argument('--duoikey', metavar="ikey",
        default="", help="ikey used for Duo authentication (Default: unset)")
    group.add_argument('--duoskey', metavar="skey",
        default="", help="skey used for Duo authentication (Default: unset)")
    group.add_argument('--duoakey', metavar="akey",
        default="", help="akey used for Duo authentication (Default: unset)")
    group.add_argument('--duohost', metavar="host",
        default="", help="host used for Duo authentication (Default: unset)")

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
             'basepath': ('X-Path', args.basepath),
             'loginpath': ('X-Path-Login', args.loginpath),
             'logoutpath': ('X-Path-Logout', args.logoutpath),
             'cookiename': ('X-Cookie-Name', args.cookiename),
             'cookiedomain': ('X-Cookie-Domain', args.cookiedomain),
             'headername': ('X-Header-Name', args.headername),
             'mfa': ('X-MFA', args.mfa),
             'logourl': ('X-Url-Logo', args.logo),
             'redirecturl': ('X-Url-Redirect', args.logoutredirect),
             'duoikey': ('X-Duo-ikey', args.duoikey),
             'duoskey': ('X-Duo-skey', args.duoskey),
             'duoakey': ('X-Duo-akey', args.duoakey),
             'duohost': ('X-Duo-host', args.duohost),
    }
    AppAuthHandler.set_params(auth_params)
    server = ThreadingHTTPServer(Listen, AppAuthHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    sys.stdout.write("[auth-app] Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()
    server.serve_forever()
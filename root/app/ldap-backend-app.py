#!/bin/sh
''''which python  >/dev/null && exec python  "$0" "$@" # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# Copyright (C) 2018 LinuxServer.io
# Copyright (C) 2020 Philipp Staiger

import sys, os, signal, cgi

import duo_web

from urllib.parse import urlparse
from http.cookies import BaseCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from cryptography.fernet import Fernet

Listen = ('0.0.0.0', 9000)
ikey = "REPLACEWITHDUOIKEY"
skey = "REPLACEWITHDUOSKEY"
akey = "REPLACEWITHDUOAKEY"
host = "REPLACEWITHDUOHOST"

class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        self.get_headers()

        url = urlparse(self.path)

        if url.path.startswith(self.path_login):
            # form cannot be generated if target is unknown
            if not self.target:
                self.log_error('target url is not passed')
                self.send_response(500)
                return
            return self.auth_form(self.target)
        if url.path.startswith(self.path_logout):
            return self.logout()

        self.send_response(200)
        self.end_headers()
        self.write_response('Hello, world! Requested URL: ' + self.path + '\n')

    def get_headers(self):

        # try to get target location from header
        self.target = self.headers.get('X-Target')

        # try to get cookie name from header
        self.cookie_name = self.headers.get('X-CookieName')
        # cookie cannot be set if name is unknown
        if self.cookie_name == None:
            self.log_error('cookie name is not passed')
            self.send_response(500)
            return

        # try to get cookie domain from header
        self.cookie_domain = self.headers.get('X-Cookie-Domain')

        # try to get logout url from header
        self.logout_url = self.headers.get('X-Url-Logout')

        # try to get logo url from header
        self.logo_url = self.headers.get('X-Url-Logo')

        # try to get login path from header
        self.path_login = self.headers.get('X-Path-Login')
        if not self.path_login or not self.path_login.startswith("/"):
            self.path_login = "/login"

        # try to get logout path from header
        self.path_logout = self.headers.get('X-Path-Logout')
        if not self.path_logout or not self.path_logout.startswith("/"):
            self.path_logout = "/logout"

        # try to get mfa method from header
        self.mfa = self.headers.get('X-MFA')
    
    # send logout message html and redirect to home.staiger.it
    def logout(self):

        logo_part = ''
        if self.logo_url and self.logo_url != '':
            logo_part = '<img class="logo" src="' + self.logo_url + '">'

        cookie_domain_part = ''
        if self.cookie_domain and self.cookie_domain != '':
            cookie_domain_part = 'domain=' + self.cookie_domain + ';'

        logout_redirect_part = ''
        if self.logout_url:
            logout_redirect_part = '<meta http-equiv="refresh" content="3;url=' + self.logout_url + '" />'

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
                <h1>You are now logged out</h1>
            </div>
        </div>
    </body>
</html>"""
        self.send_response(200)
        # Proxy Auth
        self.send_header('Set-Cookie', self.cookie_name + '=deleted; Max-Age=0; ' + cookie_domain_part + ' httponly')
        self.end_headers()
        self.write_response(html.format(redirect = logout_redirect_part, logo = logo_part))


    # send login form html
    def auth_form(self, target, message = None):

        if self.cookie_domain:
            self.cookie_domain = ''

        logo_part = ''
        if self.logo_url:
            logo_part = '<img class="logo" src="' + self.logo_url + '">'

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
        self.write_response(html.format(action = self.path_login, logo = logo_part, target = target, message = msg_part))


    # send login form html
    def duo_form(self, username, target, cookie):

        logo_part = ''
        if self.logo_url and self.logo_url != '':
            logo_part = '<img class="logo" src="' + self.logo_url + '">'

        sig_request = duo_web.sign_request(ikey, skey, akey, username)

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
        self.write_response(html.format(host = host, sig_request = sig_request, logo = logo_part, target = target))


    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        self.get_headers()

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, headers = self.headers,
                                environ = env)

        # extract required fields
        user = form.getvalue('username')
        passwd = form.getvalue('password')
        target = form.getvalue('target')

        cipher_suite = Fernet(REPLACEWITHFERNETKEY)
        message = None

        # DUO auth
        if (sig_response := form.getvalue('sig_response')) and self.mfa == "duo":
            
            username = duo_web.verify_response(ikey, skey, akey, sig_response)

            if username is None:
                # See if it was a response to an ENROLL_REQUEST
                username = duo_web.verify_enroll_response(
                    ikey, skey, akey, sig_response)
                if user is None:
                    message = 'Duo authentication failed'
                else:
                    message = ('Enrolled with Duo as %s.' % user)
            else:
            
                if auth_cookie := self.get_cookie(self.cookie_name):

                    user, mfa, passwd = self.decode_cookie(cipher_suite, auth_cookie)
                   
                    if username != user:
                        message = ("Users don't match! MFA:%s - Form: %s" % username, user)
                    if mfa: #
                        message = ("MFA already set - Should be empty! Cookie:%s - App: %s" % mfa, self.mfa)
                else:
                    message = ("Primary auth was not completed before MFA!")

        # Auth
        if user and passwd and target and not message: # and (not self.mfa or sig_response)

            # do LDAP Auth here later

            if self.mfa == "duo" and not sig_response: # Duo mfa required
                cookie = self.set_cookie(cipher_suite, user, passwd, None)
                return self.duo_form(user, target, cookie)

            if not self.mfa or self.mfa == "duo": # Auth successfull without mfa or with duo
                cookie = self.set_cookie(cipher_suite, user, passwd, self.mfa)
                self.send_response(302)
                self.send_header('Location', target)
                self.send_header('Set-Cookie', cookie)
                self.end_headers()
                return
            
        message = 'Authentication failed'
        
        return self.auth_form(target, message)

    # Encodes response and writes it out to response
    def write_response(self, response):
        self.wfile.write(response.encode("utf-8"))

    def set_cookie(self, cipher_suite, user, password, mfa = None):

        if not mfa:
            mfa = ''

        enc = user + ':' + mfa + ':' + password
        enc = cipher_suite.encrypt(enc.encode("utf-8"))
        enc = enc.decode()

        cookie_domain_part = ''
        if self.cookie_domain:
            cookie_domain_part = 'domain=' + self.cookie_domain + ';'

        return self.cookie_name + '=' + enc + '; ' + cookie_domain_part + ' httponly'
    
    def get_cookie(self, name):
        cookies = self.headers.get('Cookie')
        if cookies:
            if (authcookie := BaseCookie(cookies).get(name)):
                return authcookie.value
            else:
                return None
        else:
            return None

    def decode_cookie(self, cipher_suite, cookie):
        auth_decoded = cookie.encode("utf-8")
        auth_decoded = cipher_suite.decrypt(auth_decoded)
        auth_decoded = auth_decoded.decode("utf-8")
        return auth_decoded.split(':', 2)

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - auth-app - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    server = ThreadingHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    sys.stdout.write("[auth-app] Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()
    server.serve_forever()

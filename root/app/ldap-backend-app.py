#!/bin/sh
''''which python  >/dev/null && exec python  "$0" "$@" # '''

# Copyright (C) 2014-2015 Nginx, Inc.
# Copyright (C) 2018 LinuxServer.io

# Example of an application working on port 9000
# To interact with nginx-ldap-auth-daemon this application
# 1) accepts GET  requests on /login and responds with a login form
# 2) accepts POST requests on /login, sets a cookie, and responds with redirect

import sys, os, signal, base64, cgi
if sys.version_info.major == 2:
    from urlparse import urlparse
    from Cookie import BaseCookie
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
elif sys.version_info.major == 3:
    from urllib.parse import urlparse
    from http.cookies import BaseCookie
    from http.server import HTTPServer, BaseHTTPRequestHandler

from cryptography.fernet import Fernet

Listen = ('0.0.0.0', 9000)

import threading
if sys.version_info.major == 2:
    from SocketServer import ThreadingMixIn
elif sys.version_info.major == 3:
    from socketserver import ThreadingMixIn


def ensure_bytes(data):
    return data if sys.version_info.major == 2 else data.encode("utf-8")


class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        # for key in self.headers.keys():
        #      self.log_message('Header '+key+' : '+self.headers.get(key))

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
        if self.path_login == None or not self.path_login.startswith("/"):
            self.path_login = "/login"

        # try to get logout path from header
        self.path_logout = self.headers.get('X-Path-Logout')
        if self.path_logout == None or not self.path_logout.startswith("/"):
            self.path_logout = "/logout"

        url = urlparse(self.path)

        if url.path.startswith(self.path_login):
            return self.auth_form()
        if url.path.startswith(self.path_logout):
            return self.logout()

        self.send_response(200)
        self.end_headers()
        self.wfile.write(ensure_bytes('Hello, world! Requested URL: ' + self.path + '\n'))

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
        self.wfile.write(ensure_bytes(html.format(redirect = logout_redirect_part, logo = logo_part)))


    # send login form html
    def auth_form(self):

        # form cannot be generated if target is unknown
        if self.target == None:
            self.log_error('target url is not passed')
            self.send_response(500)
            return

        if self.cookie_domain == None:
            self.cookie_domain = ''

        logo_part = ''
        if self.logo_url and self.logo_url != '':
            logo_part = '<img class="logo" src="' + self.logo_url + '">'

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
            .log-in .content {{ margin-top: 50px; padding: 20px; text-align: center; }}
            h1, h2 {{ text-align: center; }}
            h1 {{ margin-top: 20px; margin-bottom: 20px; letter-spacing: -0.05rem; color: #565656; font-size: 1.6rem; }}
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
                <form action="{action}" method="post">
                    <p>
                        <input type="text" name="username" placeholder="Username" aria-label="Username" />
                    </p>
                    <p>
                        <input type="password" name="password" placeholder="Password" aria-label="Password" />
                    </p>
                    <!-- <p>
                        <input type="text" name="token" placeholder="2FA Token" aria-label="2FA Token" />
                    </p> -->
                    <input type="hidden" name="cookie_name" value="{cookie_name}">
                    <input type="hidden" name="cookie_domain" value="{cookie_domain}">
                    <input type="hidden" name="target" value="{target}">
                    <button type="submit" class="submit btn btn-primary">Log In</button>
                </form>
            </div>
        </div>
    </body>
</html>"""

        self.send_response(200)
        self.end_headers()
        self.wfile.write(ensure_bytes(html.format(target = self.target, cookie_name = self.cookie_name, cookie_domain = self.cookie_domain, action = self.path_login, logo = logo_part)))


    # processes posted form and sets the cookie with login/password
    def do_POST(self):

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
        cookie_name = form.getvalue('cookie_name')
        cookie_domain = form.getvalue('cookie_domain')

        # for item in form.list:
        #     if item.name and item.value:
        #         self.log_message('Field '+item.name+' : '+item.value)
        #
        # for key in self.headers.keys():
        #      self.log_message('Header '+key+' : '+self.headers.get(key))
        # for item in self.headers.items():
        #     self.log_message('Header '+item[0]+' : '+item[1])

        if user != None and passwd != None and target != None:

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie

            self.send_response(302)

            cipher_suite = Fernet(REPLACEWITHFERNETKEY)

            enc = cipher_suite.encrypt(ensure_bytes(user + ':' + passwd))
            enc = enc.decode()

            cookie_domain_part = ''
            if cookie_domain:
                cookie_domain_part = 'domain=' + cookie_domain + ';'

            self.send_header('Set-Cookie', cookie_name + '=' + enc + '; ' + cookie_domain_part + ' httponly')

            self.send_header('Location', target)
            self.end_headers()

            return

        self.log_error('some form fields are not provided')
        self.do_GET()


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
    server = AuthHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)
    sys.stdout.write("[auth-app] Start listening on %s:%d...\n" % Listen)
    sys.stdout.flush()
    server.serve_forever()

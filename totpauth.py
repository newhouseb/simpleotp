import http.cookies
import http.server
import socketserver
import random
import time
from urllib.parse import parse_qs
from cgi import parse_header, parse_multipart
import configparser
import pyotp
import logging
config = configparser.ConfigParser()
config.read('/etc/totpauth/totpauth.conf')
conf = config['TOTP']
LOGFILE = conf.get('logfile', '/var/log/totpauth/totpauth.log')
LOGLEVEL = conf.get('loglevel','INFO')
SECRETFILE = conf.get('secretfile', '/etc/totp_secret')
WINDOW = conf.getint('totp_window', 1)
PORT = conf.getint('port', 8000)
TOKEN_LIFETIME = conf.getint('token_lifetime', 60 * 60 * 24)
LOCATION = conf.get('location', '/auth')
COOKIE_NAME = conf.get('cookie_name', 'totp_token')
TITLE = conf.get('title', "Website TOTP Auth")
STYLE = conf.get('style', "")
SECURE_COOKIE = conf.getboolean('secure_cookie', True)
logging.basicConfig(filename=LOGFILE, level=LOGLEVEL, format='%(asctime)s - %(levelname)s:%(message)s', datefmt='%Y-%m-%d %H:%M:%S')

print('Logging to ' + LOGFILE)

LAST_LOGIN_ATTEMPT = 0
SECRET = open(SECRETFILE).read().strip()
FORM = """
<html>
<head>
<title>{title}</title>
<style type="text/css">
{style}
</style>
</head>
<body>
<h1>{title}</h1>
<p>
<form action="{location}/login" method="POST">
<label for="token">Enter one-time code:</label>
<input type="text" name="token">
<input type="submit" value="Submit">
</form>
</p>
</body>
</html>
""".format(title=TITLE, location=LOCATION, style=STYLE)

class TokenManager(object):
    """Who needs a database when you can just store everything in memory?"""

    def __init__(self):
        self.tokens = {}
        self.random = random.SystemRandom()

    def generate(self):
        t = '%064x' % self.random.getrandbits(8*32)
        self.tokens[t] = time.time()
        return t

    def is_valid(self, t):
        try:
            return time.time() - self.tokens.get(t, 0) < TOKEN_LIFETIME
        except Exception:
            return False

    def invalidate(self, t):
        if t in self.tokens:
            del self.tokens[t]

TOKEN_MANAGER = TokenManager()

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == LOCATION + '/check':
            # Check if they have a valid token
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if COOKIE_NAME in cookie and TOKEN_MANAGER.is_valid(cookie[COOKIE_NAME].value):
                self.send_response(200)
                self.end_headers()
                return

            # Otherwise return 401, which will be redirected to LOCATION + '/login' upstream
            self.send_response(401)
            self.end_headers()
            return

        if self.path == LOCATION + '/login':
            # Render out the login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        if self.path == LOCATION + '/logout':
            # Invalidate any tokens
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if COOKIE_NAME in cookie:
                TOKEN_MANAGER.invalidate(cookie[COOKIE_NAME].value)

            # This just replaces the token with garbage
            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie[COOKIE_NAME] = '***'
            cookie[COOKIE_NAME]["path"] = '/'
            cookie[COOKIE_NAME]["secure"] = SECURE_COOKIE
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == LOCATION + '/login':
            ip=self.headers.get("X-Real-IP")
            logging.debug("Auth attempt from " + ip)
            # Rate limit login attempts to once per second
            global LAST_LOGIN_ATTEMPT
            if time.time() - LAST_LOGIN_ATTEMPT < 1.0:
                self.send_response(429)
                self.end_headers()
                self.wfile.write(bytes('Slow down. Hold your horses', 'UTF-8'))
                logging.warning("Excessive login attempts from " + ip)
                return
            LAST_LOGIN_ATTEMPT = time.time()

            params = self.parse_POST()
            
            # Check the TOTP Secret

            submit_code = (params.get(b'token') or [None])[0].decode('utf-8')
            # The following statement can be uncommented for debugging, but should not be used on a
            #   live system to prevent log injection attacks
            #logging.debug("Submitted code is " + submit_code)

            if (pyotp.TOTP(SECRET).verify(otp=submit_code, valid_window=WINDOW)):
                logging.info("Successful auth from " + ip)
                cookie = http.cookies.SimpleCookie()
                cookie[COOKIE_NAME] = TOKEN_MANAGER.generate()
                cookie[COOKIE_NAME]["path"] = "/"
                cookie[COOKIE_NAME]["secure"] = SECURE_COOKIE

                self.send_response(302)
                self.send_header('Set-Cookie', cookie.output(header=''))
                self.send_header('Location', '/')
                self.end_headers()
                return

            # Otherwise redirect back to the login page
            else:
                logging.warning("Failed auth from " + ip)
                self.send_response(302)
                self.send_header('Location', LOCATION + '/login')
                self.end_headers()
                return
                
        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def parse_POST(self):
        """Lifted from https://stackoverflow.com/questions/4233218/"""
        ctype, pdict = parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['Content-Length'])
            postvars = parse_qs( self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        return postvars

    def log_message(self, format, *args):
        logging.debug(format%args)

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("", PORT), AuthHandler)
try:
    print("Listening on port " + str(PORT))
    logging.info("Listening on port " + str(PORT))
    httpd.serve_forever()
finally:
    httpd.server_close()




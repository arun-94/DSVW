#!/usr/bin/env python
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from cStringIO import StringIO
from SocketServer import ThreadingMixIn
from xml.etree import ElementTree

from constants import NAME, VERSION, GITHUB, AUTHOR, LISTEN_PORT, LISTEN_ADDRESS
from html import HTML_PREFIX, HTML_POSTFIX
from db import USERS_XML
from vulnerabilities import CASES

import httplib, json, os, pickle, random, re, socket, sqlite3, string, sys, subprocess, time, traceback, urllib

try:
    import lxml.etree
except ImportError:
    msg = ("apt-get install python-lxml"
           if not subprocess.mswindows else
           "https://pypi.python.org/pypi/lxml")

    print ("[!] please install 'python-lxml' to (also) get access to XML vulnerabilities (e.g. '%s')\n" % msg)


# LISTEN_ADDRESS = "10.245.204.10810.245.204.108"


def init():
    global connection
    HTTPServer.allow_reuse_address = True
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute(
            "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, "
            "password TEXT)")
    cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)",
                       ((_.findtext("username"), _.findtext("name"), _.findtext("surname"), _.findtext("password")) for
                        _ in ElementTree.fromstring(USERS_XML).findall("user")))
    cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")


class ReqHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
        code, content, params, cursor = httplib.OK, HTML_PREFIX, dict((match.group("parameter"), urllib.unquote(
                ','.join(re.findall(r"(?:\A|[?&])%s=([^&]+)" % match.group("parameter"), query)))) for match in
                                                                      re.finditer(
                                                                              r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)("
                                                                              r"[^&]+)",
                                                                              query)), connection.cursor()
        try:
            if path == '/':
                if "id" in params:
                    cursor.execute("SELECT id, username, name, surname FROM users WHERE id=" + params["id"])
                    content += "<div><span>Result(" \
                               "s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname" \
                               "</th></thead>%s</table>%s" % (
                                   "".join("<tr>%s</tr>" % "".join(
                                           "<td>%s</td>" % ("-" if _ is None else _) for _ in row) for row in
                                           cursor.fetchall()), HTML_POSTFIX)
                elif "v" in params:
                    content += re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], HTML_POSTFIX)
                elif "object" in params:
                    content = str(pickle.loads(params["object"]))
                elif "path" in params:
                    content = (
                        open(os.path.abspath(params["path"]), "rb") if not "://" in params["path"] else urllib.urlopen(
                                params["path"])).read()
                elif "domain" in params:
                    content = subprocess.check_output("nslookup " + params["domain"], shell=True,
                                                      stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
                elif "xml" in params:
                    content = lxml.etree.tostring(
                            lxml.etree.parse(StringIO(params["xml"]), lxml.etree.XMLParser(no_network=False)),
                            pretty_print=True)
                elif "name" in params:
                    found = lxml.etree.parse(StringIO(USERS_XML)).xpath(
                            ".//user[name/text()='%s']" % params["name"])
                    content += "<b>Surname:</b> %s%s" % (found[-1].find("surname").text if found else "-", HTML_POSTFIX)
                elif "size" in params:
                    start, _ = time.time(), "<br>".join("#" * int(params["size"]) for _ in range(int(params["size"])))
                    content += "<b>Time required</b> (to 'resize image' to %dx%d): %.6f seconds%s" % (
                        int(params["size"]), int(params["size"]), time.time() - start, HTML_POSTFIX)
                elif "comment" in params or query == "comment=":
                    if "comment" in params:
                        cursor.execute(
                                "INSERT INTO comments VALUES(NULL, '%s', '%s')" % (params["comment"], time.ctime()))
                        content += "Thank you for leaving the comment. Please click here <a " \
                                   "href=\"/?comment=\">here</a> to see all comments%s" % HTML_POSTFIX
                    else:
                        cursor.execute("SELECT id, comment, time FROM comments")
                        content += "<div><span>Comment(" \
                                   "s):</span></div><table><thead><th>id</th><th>comment</th><th>time</th></thead>%s" \
                                   "</table>%s" % (
                                       "".join("<tr>%s</tr>" % "".join(
                                               "<td>%s</td>" % ("-" if _ is None else _) for _ in row) for row
                                               in cursor.fetchall()), HTML_POSTFIX)
                elif "include" in params:
                    backup, sys.stdout, program, envs = sys.stdout, StringIO(), (
                        open(params["include"], "rb") if not "://" in params["include"] else urllib.urlopen(
                                params["include"])).read(), {"DOCUMENT_ROOT"  : os.getcwd(),
                                                             "HTTP_USER_AGENT": self.headers.get("User-Agent"),
                                                             "REMOTE_ADDR"    : self.client_address[0],
                                                             "REMOTE_PORT"    : self.client_address[1], "PATH": path,
                                                             "QUERY_STRING"   : query}
                    exec (program) in envs
                    content += sys.stdout.getvalue()
                    sys.stdout = backup
                elif "redir" in params:
                    content = content.replace("<head>",
                                              "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % params[
                                                  "redir"])
                if HTML_PREFIX in content and HTML_POSTFIX not in content:
                    content += "<div><span>Attacks:</span></div>\n<ul>%s\n</ul>\n" % ("".join(
                            "\n<li%s>%s - <a href=\"%s\">vulnerable</a>|<a href=\"%s\">exploit</a>|<a href=\"%s\" "
                            "target=\"_blank\">info</a></li>" % (
                                " class=\"disabled\" title=\"module 'python-lxml' not installed\"" if (
                                        "lxml.etree" not in sys.modules and any(
                                        _ in case[0].upper() for _ in ("XML", "XPATH"))) else "", case[0], case[1],
                                case[2], case[3]) for case in CASES)).replace("<a href=\"None\">vulnerable</a>|",
                                                                              "<b>-</b>|")
            elif path == "/users.json":
                content = "%s%s%s" % ("" if not "callback" in params else "%s(" % params["callback"], json.dumps(dict(
                        (_.findtext("username"), _.findtext("surname")) for _ in
                        ElementTree.fromstring(USERS_XML).findall("user"))),
                                      "" if not "callback" in params else ")")
            elif path == "/login":
                cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username",
                                                                                                        "")) + "' AND "
                                                                                                               "password='" + params.get(
                        "password", "") + "'")
                content += "Welcome <b>%s</b><meta http-equiv=\"Set-Cookie\" content=\"SESSIONID=%s; path=/\"><meta " \
                           "http-equiv=\"refresh\" content=\"1; url=/\"/>" % (
                               re.sub(r"[^\w]", "", params.get("username", "")),
                               "".join(random.sample(string.letters + string.digits,
                                                     20))) if cursor.fetchall() else "The username and/or password is " \
                                                                                     "" \
                                                                                     "" \
                                                                                     "" \
                                                                                     "incorrect<meta " \
                                                                                     "http-equiv=\"Set-Cookie\" " \
                                                                                     "content=\"SESSIONID=; path=/; " \
                                                                                     "expires=Thu, " \
                                                                                     "01 Jan 1970 00:00:00 GMT\">"
            else:
                code = httplib.NOT_FOUND
        except Exception, ex:
            content = ex.output if isinstance(ex, subprocess.CalledProcessError) else traceback.format_exc()
            code = httplib.INTERNAL_SERVER_ERROR
        finally:
            self.send_response(code)
            self.send_header("Connection", "close")
            self.send_header("X-XSS-Protection", "0")
            self.send_header("Content-Type", "%s%s" % (
                "text/html" if content.startswith("<!DOCTYPE html>") else "text/plain",
                "; charset=%s" % params.get("charset", "utf8")))
            self.end_headers()
            self.wfile.write(
                    "%s%s" % (content, HTML_POSTFIX if HTML_PREFIX in content and GITHUB not in content else ""))
            self.wfile.flush()
            self.wfile.close()


class ThreadingServer(ThreadingMixIn, HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        HTTPServer.server_bind(self)


if __name__ == "__main__":
    init()
    print "%s #v%s\n by: %s\n\n[i] running HTTP server at '%s:%d'..." % (NAME, VERSION, AUTHOR,
                                                                         LISTEN_ADDRESS, LISTEN_PORT)
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception, ex:
        print "[x] exception occurred ('%s')" % ex
    finally:
        os._exit(0)

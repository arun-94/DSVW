from constants import NAME

import cgi

HTML_PREFIX = '''<!DOCTYPE html>
<html>
<head>
<style>a {font-weight: bold; text-decoration: none; visited: blue; color: blue;} ul {display: inline-block;} 
.disabled {text-decoration: line-through; color: gray} .disabled a {visited: gray; color: gray; pointer-events: none; 
cursor: default} table {border-collapse: collapse; margin: 12px; border: 2px solid black} th, td {border: 1px solid 
black; padding: 3px} span {font-size: larger; font-weight: bold}</style>
<title>%s</title>
</head>
<body style='font: 12px monospace'>
<script>
    function process(data) {
        alert("Surname(s) from JSON results: " + Object.keys(data).map(function(k) {return data[k]}));
    };
    var index=document.location.hash.indexOf('lang='); 
    if (index != -1) document.write('<div style="position: absolute; top: 5px; right: 5px;">Chosen language: <b>' + 
    decodeURIComponent(document.location.hash.substring(index + 5)) + '</b></div>');
</script>
''' % cgi.escape(NAME)

HTML_POSTFIX = '''</body>
</html>
'''
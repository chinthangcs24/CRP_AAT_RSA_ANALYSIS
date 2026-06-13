from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

PORT = 4443

httpd = HTTPServer(
    ('localhost', PORT),
    SimpleHTTPRequestHandler
)

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

context.set_ciphers("ALL:@SECLEVEL=0")

context.load_cert_chain(
    certfile="fermat.crt",
    keyfile="fermat.pem"
)

httpd.socket = context.wrap_socket(
    httpd.socket,
    server_side=True
)

print(f"Running at https://localhost:{PORT}")

httpd.serve_forever()
#!/usr/bin/env python3
import sys, os, ssl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app import app

def get_ssl_context():
    """Get SSL context if certificates are configured."""
    cert_file = os.environ.get('SSL_CERT')
    key_file = os.environ.get('SSL_KEY')
    
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        return ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    return None

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    ssl_context = get_ssl_context()
    
    if ssl_context:
        ssl_context.load_cert_chain(
            os.environ.get('SSL_CERT'),
            os.environ.get('SSL_KEY')
        )
        print(f"Running with HTTPS on port {port}")
    else:
        print(f"Running with HTTP on port {port} (configure SSL_CERT and SSL_KEY for HTTPS)")
    
    app.run(debug=False, host='0.0.0.0', port=port, ssl_context=ssl_context)

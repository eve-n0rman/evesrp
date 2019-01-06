#!/usr/bin/env python
import os.path
import sys
sys.path.append("/opt/python/current/app/src")
from evesrp import create_app
from werkzeug.contrib.fixers import ProxyFix

application = create_app(instance_path=os.path.abspath(os.path.dirname(__file__)))
application.config['PREFERRED_URL_SCHEME'] = u'https'

if __name__ == '__main__':
    application.run()
else:
    application.wsgi_app = ProxyFix(application.wsgi_app)

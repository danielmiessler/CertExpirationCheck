# Credit to phreakmonkey.com / phreakmonkey at gmail 
# For OS X, brew install swig, then easy_install M2Crypto
# Modified the original code to only output expiration date

import sys
import socket
import string

from M2Crypto import SSL

def reportIP(IPaddress):
   ctx = SSL.Context()
   ctx.set_allow_unknown_ca(True)
   ctx.set_verify(SSL.verify_none, 1)
   conn = SSL.Connection(ctx)
   conn.postConnectionCheck = None
   timeout = SSL.timeout(15)
   conn.set_socket_read_timeout(timeout)
   conn.set_socket_write_timeout(timeout)
   try:
#     sys.stderr.write('Connecting '+IPaddress+'. ')
      sys.stderr.flush()
      conn.connect((IPaddress, 443))
   except:
      print IPaddress+"|{SSL_HANDSHAKE_FAILED}|"+"|"+"|"+"|"
      sys.stderr.write('failed.\n')
      sys.stderr.flush()
      return
#  sys.stderr.write('Getting cert info. ')
   sys.stderr.flush()

   cert = conn.get_peer_cert()
   try:
      cissuer = cert.get_issuer().as_text()
   except:
      sys.stderr.write("Error:  No Valid Cert Presented\n");
      print IPaddress+"|{NO_CERT_PRESENTED}|"+"|"+"|"+"|"
      sys.stderr.flush
      conn.close
      return

#  sys.stderr.write('done\n')
   sys.stderr.flush()
      
   csubject = cert.get_subject().as_text()
   try:
      cAltName = cert.get_ext('subjectAltName').get_value()
   except LookupError:
      cAltName = ""
   try:
      cCN = cert.get_subject().CN
   except AttributeError:
      cCN = ""
   try:
      cExpiry = str(cert.get_not_after())
   except AttributeError:
      cExpiry = ""
   conn.close
   #print IPaddress+"|"+cCN+"|"+csubject+"|"+cissuer+"|"+cAltName+"|"+cExpiry
   print cExpiry

reportIP(sys.argv[1])

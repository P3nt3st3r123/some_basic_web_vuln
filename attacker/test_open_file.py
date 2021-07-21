import os

DIR = os.path.dirname(os.path.realpath(__file__))
# https://www.ibm.com/docs/en/sva/9.0.2.1?topic=tasks-valid-characters-ldap-user-group-names
# https://help.sap.com/doc/saphelp_aii710/7.1/en-US/a8/d3c2aa14b04bf8bb2718aefeb478f5/content.htm?no_cache=true
# https://portswigger.net/web-security/file-path-traversal
if __name__=='__main__':
	tmp = f"{DIR}/solve.py{bytes(i for i in range(256)).replace(bytes([92]),b'').replace(bytes([47]),b'').replace(b'.',b'').replace(bytes(1),b'').decode('Latin1')}/../solve.py"
	tmp = os.path.normpath(tmp)
	print(tmp)
	f = open(tmp,'rb')
	print(f.read())
	print(tmp.encode("Latin1"))
	f.close()
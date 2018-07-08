from time import time

from collections import OrderedDict
import hashlib
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import json
import requests
from flask import Flask, jsonify, request, render_template

MINER_ADDRESS = '01234_WALLET_56789'
HOST = '127.0.0.1'

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

    def register_node(self, port):
        if port not in self.nodes:
            node = HOST + ':' + str(port)
            self.nodes.add(node)
        else:
            raise ValueError('Invalid PORT! Its taken!')


    def check_is_valid(self):
       return self.is_chain_valid(self.chain)

    @staticmethod
    def calculate_hash(previous_hash, timestamp, nonce):
        string = (previous_hash + str(timestamp) + str(nonce)).encode()
        calculated_hash = hashlib.sha256(string).hexdigest()
        
        return calculated_hash

    @staticmethod
    def is_chain_valid(chain):
        current_index = 1

        while current_index < len(chain):
            current_block = chain[current_index]
            last_block = chain[current_index - 1]
            print(last_block['hash'])
            print(current_block['previous_hash'])
            print("\n---------\n")
            
            # provjera da li je trenutni hash jednak registriranom hashu
            if not current_block['hash'] == Blockchain().calculate_hash(current_block['previous_hash'], current_block['timestamp'], current_block['nonce']):
                print("Current hashes not equal")
                return False

            # provjera da li je prijasnji hash i registrirani prijasni hash jedanki
            if not last_block['hash'] == current_block['previous_hash']:
                print("Previous hashes not equal")
                return False

            current_index += 1

        #print("LEGIT CHAIN")
        return True

class Block:
    DIFFICULTY = 3 # tezina rudarenja, broj prvih nula hash-a
    NONCE = 1 # unikatni broj koji zadovoljava hash s tezinom (krece od 1)
    BLOCK_REWARD = 1 # nagrada miner-u

    def __init__(self, previous_hash, transactions):
        self.index = len(blockchain.chain) + 1
        self.previous_hash = previous_hash
        self.timestamp = time()
        self.transactions = transactions # lista transakcija
        self.hash = self.calculate_hash()
        self.reward = 0

    def calculate_hash(self):
        string = (self.previous_hash + str(self.timestamp) + str(self.NONCE)).encode()
        #string = (self.previous_hash + str(self.timestamp) + self.transactions + str(self.NONCE)).encode()
        calculated_hash = hashlib.sha256(string).hexdigest() # dva puta sha256 ?
        
        return calculated_hash

    def proof_of_work(self):
        target_hash = self.DIFFICULTY * "0"
        block_hash = ''

        while not block_hash[:self.DIFFICULTY] == target_hash:
            self.NONCE += 1
            block_hash = self.calculate_hash()
        print("Block Mined!!! : " + block_hash)
        
        return block_hash  

    def to_dict(self):
        block_dict = {
            'block_number': block.index,
            'hash': block.hash,
            'transactions': block.transactions,
            'previous_hash': block.previous_hash,
            'nonce': block.NONCE,
            'miner_reward': block.BLOCK_REWARD,
            'timestamp': block.timestamp
        }

        return block_dict

class Transaction:
    def __init__(self, sender_address, recipient_address, value):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.value = value

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def submit_transaction(self, sender_private_key):
        transaction = self.to_dict()
        
        self.signature = self.__generate_signature(sender_private_key, transaction)

        return True

    def __generate_signature(self, sender_private_key, transaction):
        private_key = RSA.importKey(binascii.unhexlify(sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(transaction).encode('utf8'))
        
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    def verify_transaction(self):
        transaction = OrderedDict({
                'sender_address': self.sender_address, 
                'recipient_address': self.recipient_address,
                'value': self.value
            })
        
        public_key = RSA.importKey(binascii.unhexlify(self.sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        
        verifier = verifier.verify(h, binascii.unhexlify(self.signature))
        return verifier

class Wallet:
    def __init__(self):
        self.generate_keys()

    def generate_keys(self):
        random_gen = Crypto.Random.new().read
        private_key = RSA.generate(1024, random_gen)
        public_key = private_key.publickey()

        self.private_key = binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii')
        self.public_key = binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii') 


app = Flask(__name__)
blockchain = Blockchain()
blockchain.register_node(5000)
block = Block("1", "GENESIS BLOCK")
block_dict = {
    'block_number': "1",
    'hash': block.hash,
    'transactions': block.transactions,
    'previous_hash': "0",
    'nonce': "1",
    'miner_reward': "0",
    'timestamp': block.timestamp
}

blockchain.chain.append(block_dict)
blockchain.is_chain_valid(blockchain.chain)


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    wallet = Wallet()
    wallet.generate_keys()
	
    response = {
		'private_key': wallet.private_key,
		'public_key': wallet.public_key
	}

    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    # provjeri da li su potrebna polja stigla preko POST-a
    values = request.get_json()
    required = ['sender_address', 'sender_private_key', 'recipient_address', 'value']
    if not all(k in values for k in required):
        return 'Missing values', 400

    sender_address = values['sender_address']
    sender_private_key = values['sender_private_key']
    recipient_address = values['recipient_address']
    value = values['value']
    #value = request.json['value']

    transaction = Transaction(sender_address, recipient_address, value)
    transaction.submit_transaction(sender_private_key)

    # i dodati u blockchain trenutnu listu transakcija za u blok
    
    blockchain.current_transactions.append(transaction)
    
    # index iduceg bloka...
    index = int(blockchain.chain[-1]['block_number']) + 1

    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.signature,
        'message': f'Transaction will be added to Block {index}'
        }

    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    if not blockchain.current_transactions:
        return 'No transactions for block', 400
    
    #provjeriti ispravnost transakcija
    
    last_block = blockchain.chain[-1]
    previous_hash = last_block['hash']
    block = Block(previous_hash, blockchain.current_transactions)
    print('Mining block ...')
    block.proof_of_work()
    # dodati nagradu mineru
    block.reward = Transaction("Reward for mining", MINER_ADDRESS, block.BLOCK_REWARD)
    transactions_string = json.dumps([ob.__dict__ for ob in block.transactions])
    
    block_dict = {
        'hash': block.hash,
        'block_number': block.index,
        'transactions': transactions_string,
        'previous_hash': block.previous_hash,
        'nonce': block.NONCE,
        'miner_reward': block.reward.to_dict(),
        'timestamp': block.timestamp
    }

    blockchain.chain.append(block_dict)
   # blockchain.current_transactions = []

    response = {
        'message': "New Block Forged",
        'hash': block.hash,
        'block_number': block.index,
        'transactions': transactions_string,
        'previous_hash': block.previous_hash,
        'nonce': block.NONCE,
        'miner_reward': block.reward.to_dict(),
    }
    
    return jsonify(response), 200
    
@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    
    return jsonify(response), 200

@app.route('/valid', methods=['GET'])
def is_valid():
    res = 'LEGIT' if blockchain.check_is_valid() else 'KORUPCIJA'
    response = {'valid': res}
    
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host=HOST, port=5000)    
    
    '''
    alice = Wallet()
    bob = Wallet()

    print("ALICE ---- PRIVATE KEY: ", alice.private_key)
    print("\n-----------------\n")

    print("Radimo transakciju: ...")
    transaction = Transaction(alice.public_key, bob.public_key, 5)
    transaction.submit_transaction(alice.private_key)
    print("Da li je verificirana ?: ")
    print(transaction.verify_transaction())
    print("\n-----------------\n")
    
    print("Dodavanje transakcija u blok:")
    
    for i in range(1,5):
        prev_block = blockchain.chain[i-1]
        prev_hash = prev_block['hash']
        transaction = Transaction(alice.public_key, bob.public_key, 5*i)
        block = Block(prev_hash, transaction)
        print("Rudarenje bloka {} ... ".format(i))
        block.hash = block.proof_of_work()
        blockchain.chain.append(block.to_dict())

    print("Da li je lanac validan ...")
    blockchain.check_is_valid()
    print("\n-----------------\n")


POSTMAN + FLASK

> wallet, generiranje kljuceva koristenjem RSA
> transakcije, slanje vrijednosti s jednog na drugi racun (bez double spending validacije)
> blokovi za spremanje podataka
> digitalni potpisi (sha256) za povezivanje blokova u lanac = INTEGRITET
> proof of work, rudarenje za validaciju blokova
> provjera da li je lanac validan i ne mijenjan
> nodes, consesus (?), IMPLEMENTIRATI
> merkle tree (?), IMPLEMENTIRATI
'''
import hashlib as hasher
from datetime import datetime
import requests
from flask import Flask, request, jsonify
import json
import pki
from pki import NomadWallet, craft_pem_file, breakdown_pem_file, read_public_key

class Transaction:
    #Builds class constructor
    #index = [block_index, transaction_index]
    #to = public key of destination address
    #source = public key of source address
    #amount = amount of value to be transferred
    #data = {'transaction_type':'', 'transaction data':{}}
    #signatures = {'public_key':'', 'signature':[time.now(), 'signature']
    def __init__(self, index, source, destination, signatures, amount=0, data=None):
        self.index = index
        self.source = source
        self.destination = destination
        self.amount = amount
        self.data = data
        self.signatures = signatures

    def __repr__(self):
        return f'''{str(type(self))[19:-2]}(index = {self.index}, source = {"'"+self.source+"'"}, destination = {"'"+self.destination+"'"}, amount = {self.amount}, data = {self.data}, signatures = {self.signatures})'''

    def __str__(self):
        transaction = {
            'index':self.index,
            'source':self.source,
            'destination':self.destination,
            'amount':self.amount,
            'data':self.data,
            'signatures':self.signatures
            }
        return json.dumps(transaction)

    def content(self):
        transaction = {
            'index':self.index,
            'source':self.source,
            'destination':self.destination,
            'amount':self.amount,
            'data':self.data
            }
        return json.dumps(transaction)

    def sign(self, wallet):
        signature = wallet.sign(self.content())
        s = {'address':wallet.string_public_key, 'timestamp':datetime.now(), 'signature':signature}
        self.signatures.append(s)
        if self.signatures[-1] == s:
            return "Success"
        else:
            return "False"

    def verify_signatures(self):
        for signature in self.signatures:
            #Load wallet from Public Key string
            craft_pem_file(signature['address'],'./Keys/Public/')
            #Verify signature using wallet and return result
            wallet.verify_signature(signature['signature'])




    def verify(self,blockchain):
        #Verifies that the source wallet has the necessary funds for the transaction
        if blockchain.address_balance(self.source) < self.amount:
            print("Insufficient Funds in Source Wallet")
            return False

        #
            return False

#data = ['Decrypted',{
    #'encrypted_index':[block_index, transaction_index],
    #'encryption_method':['Public Key Method']
    #'encryption_key':destination of classified transaction
    #'decrypted_transaction':original decrypted transaction data
    #}]
class DecryptedTransaction(Transaction):
    #Returns decrypted transaction data in the following form: [transaction_type, transaction_data]
    def decrypt_transaction_data(self):
        #REPLACE#
        return self.data[1]['decrypted_transaction']

    #Returns True if transaction is valid and False if it is invalid
    def verify(self, blockchain):
        #Executes basic transaction.verify()
        if super().verify():
            #Attempts to decrypt the transaction at encrypted_index
            decrypted_transaction_data = self.decrypt_transaction_data()

            #Compares decrypted transaction to provided transaction
            if self.data[1]['decrypted_transaction'] == decrypted_transaction_data:
                #Initiates decrypted transaction
                transaction = eval(self.data[1])
                #Verifies decrypted transaction
                if transaction.verify():
                    return True
                else:
                    if self.destination == transaction.source:
                        if self.source == transaction.destination:
                            if self.amount == transaction.amount:
                                return True
                            else:
                                print("Invalid Amount: " + str(self.amount) + "\nCorrect Amount: " + str(transaction.amount))
                        else:
                            print("Invalid Source Address: " + str(self.source) + "\nCorrect Source Address: " + str(transaction.source))
                    else:
                        print("Invalid Destination Address: " + str(self.destination) + "\nCorrect Destination Address: " + str(transaction.destination))
            else:
                print("Transactions do not match...")
        else:
            return False

class Block:
    def __init__(self, index, miner, previous_nonce=None, current_hash=None, signature=None, timestamp=None, data=[]):
        self.index = index
        self.previous_nonce = previous_nonce
        self.current_hash = current_hash
        self.miner = miner
        self.signature = signature
        self.data = data

    def __repr__(self):
        return f'Block(index={self.index}, miner={self.miner}, previous_nonce={self.previous_nonce}, current_hash={self.current_hash}, signature={self.signature}, data={self.data})'

    def __str__(self):
        return json.dumps({'index':self.index, 'previous_nonce':self.previous_nonce, 'current_hash':self.current_hash, 'signature':self.signature, 'data':self.data})

    def str_no_signatures(self):
        return json.dumps({'index':self.index, 'previous_nonce':self.previous_nonce, 'current_hash':self.current_hash, 'data':self.data})

    def authenticate(self, blockchain):
        #Pull the last block from the blockchain
        last_block = blockchain.blocks[-1]
        #Verify previous_hash against the last block in blockchain
        if self.previous_hash != last_block.current_hash:
            print("Previous Hash is incorrect.")
            return False

        #Authenticate previous_nonce against the last block in blockchain
        #if self.previous_hash != hash_function(str(previous_nonce) + last_block_contents):
            #print("Nonce is incorrect.")
            #return True

        #Authenticate block signature using miner's address


        #Authenticate transactions in block data
        failed_transactions = [transaction.index for transaction in self.data if transaction.authenticate(blockchain) == False]
        if len(failed_transactions) > 0:
            print("The following transactions failed to authenticate.")
            for index in failed_transactions:
                print("    "+index)
            return False

        #If all parameters are met, return True
        return True

    def hash_block(self, nonce=None):
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.previous_nonce) + str(self.previous_hash) + str(self.miner) + str(self.signature)).encode('utf8'))
        if type(nonce) == 'string' and nonce != None:
            sha.update(str(previous_nonce).encode('utf8'))
        self.hash = sha.hexdigest()

    def check_block_nonce(self, nonce, blockchain):
        if self.hash_block(nonce) == blockchain.blocks[-1].current_hash:
            return True
        else:
            return False

    def add_transactions(self,transactions):
        for transaction in transactions:
            self.data.append(transaction)

class Genesis_Block(Block):
    def __init__(self,miner_wallet):
        super().__init__(index=0, miner=breakdown_pem_file('Keys/Public/NOMAD.pem'), previous_nonce=0, timestamp=str(datetime.now()))
        wallet = read_public_key('Keys/Public/NOMAD.pem')
        self.add_transactions[
                            {'type':'EntityTransaction','data':str(Transaction(source=breakdown_pem_file('Keys/Public/NOMAD.pem'), destination=breakdown_pem_file('Keys/Public/NOMAD.pem'), amount=0, data={'Name':'NOMAD'}).sign())},
                            {},
                            {}
                            ]

class BlockChain:
    def __init__(self):
        self.blockchain = []
        self.nodes = [] #Node Address = "127.0.0.1"
        self.create_genesis_block()
        self.current_block = Block(len(self.blockchain),[],json.loads(self.blockchain[len(self.blockchain)-1])['hash']) #Current Transactions
        self.last_proof = self.blockchain[0]['proof']

    def add_node(self, node_url):
        self.nodes.append(node_url)

    def create_genesis_block(self):
        #Initiates genesis block
        genesis_block = Block(0, "0")

        #A list of transactions to be included in the genesis block
        genesis_block.add_transactions([str(Transaction(index=0, source='#', destination='NETWORK', amount=25000000, signatures=[{'#':'ABCD'}]))])
        wallet1 = NomadWallet()
        wallet2 = NomadWallet()
        genesis_block.add_transactions([str(Transaction(index=1, source='NETWORK', destination=wallet1.string_public_key, amount=10, signatures=[{'NETWORK':'DEFG'}]))])
        genesis_block.add_transactions([str(Transaction(index=2, source=wallet1.string_public_key, destination=wallet2.string_public_key, amount=2, signatures=[{wallet1.string_public_key:'HIJK'}]))])
        self.blockchain.append(str(genesis_block))

    def proof_of_work(self):
        incrementor = self.last_proof + 1
        while not (incrementor % 9 == 0 and incrementor % self.last_proof == 0):
            incrementor += 1
            if incrementor % 100 == 0:
                #Check if the current proof has already been found
                if update_blockchain(self.nodes):
                    incrementor = self.last_proof + 1
                    self.current_block.previous_hash = self.blockchain[len(self.blockchain)-1].hash
        return incrementor

    #Returns True if this node's current proof of work matches the networks, and False if a new proof of work needs to be started
    def update_blockchain(self):
        update = False
        for node_url in self.nodes:
            # Get other chains using a GET request
            node_chain = requests.get(node_url + "/blocks").content
            # Convert the JSON object to a Python dictionary
            node_chain = json.loads(node_chain)
            blocks = node_chain['blocks']
            if blocks == self.blockchain:
                pass
            if len(blocks) > len(self.blockchain):
                self.blockchain = blocks
                update = True
        return update

    #Return True if blockchain is valid
    def verify_blockchain(consensus_mode,blockchain):
        incrementor = 1
        while incrementor <= len(self.blockchain):
            if self.blockchain[incrementor-1].proof != self.blockchain[incrementor]:
                return False
        return True

    #blockchain=Patchwork BlockChain,index=[BlockIndex,TransactionIndex]
    def retrieve_transaction(self,index,type=''):
        transaction = self.blockchain[index[0]]['data'][index[1]]['data']
        transaction_type = transaction[0]
        transaction_data = transaction[1]

        #Checks the transaction type
        if transaction_type == 'Version':
            return transaction_data
        if transaction_type == type or type == '':
            return eval(transaction_data)
        else:
            return 'Invalid Transaction'

    def address_balance(self, address):
        balance = 0
        #Iterates through each block in the blockchain
        for block in self.blockchain:
            #Iterates through each transaction in the current block
            for transaction in block['data']:
                transaction = json.loads(transaction)
                #Checks if current transaction is subclass of Transaction
                if transaction['source'] == address:
                    balance = balance - transaction['amount']

                if transaction['destination'] == address:
                    balance = balance + transaction['amount']
        return balance

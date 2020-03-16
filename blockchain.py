import hashlib as hasher
from datetime import datetime
import requests
from flask import Flask, request, jsonify
import json
import pki
from pki import NomadWallet, craft_public_pem, breakdown_pem_file, read_public_key
from poc import *
import os

class Transaction:
    #Builds class constructor
    #index = [block_index, transaction_index]
    #to = public key of destination address
    #source = public key of source address
    #amount = amount of value to be transferred
    #data = {'transaction_type':'', 'transaction data':{}}
    #signatures = {'public_key':'', 'signature':[time.now(), 'signature']
    def __init__(self, source, destination, signatures, amount=0, data=None, index=None):
        #Transaction variables
        self.source = source
        self.destination = destination
        self.amount = amount
        self.data = data
        self.signatures = signatures
        #Block variables
        self.index = index

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

    def as_dict(self):
        return {
            'index':self.index,
            'source':self.source,
            'destination':self.destination,
            'amount':self.amount,
            'data':self.data,
            'signatures':self.signatures
            }
    def content(self):
        transaction = {
            'source':self.source,
            'destination':self.destination,
            'amount':self.amount,
            'data':self.data
            }
        return json.dumps(transaction)

    def sign(self, wallet):
        timestamp = str(datetime.now())
        signature = wallet.sign(self.content()+timestamp)
        s = {'address':wallet.string_public_key, 'timestamp':timestamp, 'signature':str(signature)}
        self.signatures.append(s)
        if self.signatures[-1] == s:
            return "Success"
        else:
            return "False"

    def verify_signatures(self):
        auth = []
        for signature in self.signatures:
            filename = './Keys/Public/public.pem'
            craft_public_pem(signature['address'], filename)
            wallet = NomadWallet(public_key = read_public_key(filename))
            #Verify signature using wallet and return result
            signature_status = wallet.verify_signature(signature['signature'],self.content()+str(signature['timestamp']))
            if signature_status:
                auth.append([signature_status,'Success'])
            else:
                auth.append([signature_status,'Failure'])
        return auth

    def validate(self):
        #Verify that amount is positive
        if self.amount < 0:
            return [False, 'Amount must be positive.']
        #Validate signatures
        i = 0
        invalid=[]
        for signature in self.signatures:
            if self.source == signature['address']:
                for status in self.verify_signatures():
                    if status[0] == False:
                        invalid.append([i,status[1]])
                if len(invalid) != 0:
                    return [False, str(invalid)]
                return [True, 'Success']
        return [False, 'Source Signature Not Present']

class RDSTransaction:
    def __init__(self, source, destination, signatures, data, amount=0, index=None):
        if type(data) is not dict:
            return 'Data must be in dictionary format...'
        if 'transaction_type' not in data.keys():
            return 'transaction_type required...'
        if data['transaction_type'] != 'RDSTransaction':
            return 'transaction_type must be RDSTransaction'
        super().__init__(self, source, destination, signatures, data, amount, index)

    def download(self):
        file_id = self.data['data']['file_id']
        url = self.data['data']['url']
        return requests.get(url+'/shards/'+file_id).content


class Block:
    #Builds the Block Item Using the Parameters Below
    def __init__(self, miner=None, source_node=None, block_index=None, proof={}, signatures=[], data=[]):
        #Block variables
        self.miner = miner #Miner's Public Key, Must Match Scoop Encryption
        self.source_node = source_node #Source Node's Public Key
        self.signatures = signatures #
        self.data = data #Contains All Transactions Within the Block

        #BlockChain variables
        self.block_index = block_index #Represents the Block's Index Within the BlockChain
        self.proof = proof #Proof contains nonce and scoop

    #Returns a String That Can Be Executed to Create the Same Block Item
    def __repr__(self):
        return f'Block(miner="{self.miner}", source_node="{self.source_node}", signatures={self.signatures}, data={self.data}, block_index={self.block_index}, proof={self.proof})'

    #Returns a Human-Readable Form of the Block Item's Contents
    def __str__(self):
        return json.dumps({'miner':self.miner, 'source_node':self.source_node, 'signatures':str(self.signatures), 'data':self.data, 'block_index':self.block_index, 'proof':self.proof})

    #Returns a Human-Readable Form of the Block Item's Contents
    def as_dict(self):
        return {
                'miner':self.miner,
                'source_node':self.source_node,
                'signatures':str(self.signatures),
                'data':self.data,
                'block_index':self.block_index,
                'proof':self.proof
                }

    #Returns the Block Data to be Used for Block Signatures
    def content(self):
        return json.dumps({'data':self.data})

    def verify_signature_exists(self, address):
        for signature in self.signatures:
            if signature['adress'] == adress:
                return [True, 'Success!']
        return [False, 'Signature Not Present.']

    def validate(self):
        #Authenticate block signature using miner's address
        miner_status = self.verify_signature_exists(self.miner)
        if miner_status == False:
            return [False, 'Miner signature required...']
        #Authenticate block signature using source node's address
        node_status = self.verify_signature_exists(self.source_node)
        if node_status == False:
            return [False, 'Node signature required...']
        #Authenticate transactions in block data
        failed_transactions = [transaction.index for transaction in self.data if transaction.validate() == False]
        if len(failed_transactions) > 0:
            print("The following transactions failed to authenticate.")
            for index in failed_transactions:
                print("    "+index)
            return [False, 'The following transactions failed to authenticate: ' + ','.join(map(str, failed_transactions))]

        #If all parameters are met, return True
        return [True, 'Success']

    def sign(self, wallet):
        timestamp = str(datetime.now())
        signature = wallet.sign(self.content()+timestamp)
        s = {'address':str(wallet.string_public_key), 'timestamp':timestamp, 'signature':str(signature)}
        self.signatures.append(s)
        if s in self.signatures:
            return "Success"
        else:
            return "False"

    def hash_block(self, nonce=None):
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.previous_nonce) + str(self.previous_hash) + str(self.miner) + str(self.signature)).encode('utf8'))
        if type(nonce) == 'string' and nonce != None:
            sha.update(str(previous_nonce).encode('utf8'))
        self.hash = sha.hexdigest()


    def add_transactions(self,transactions):
        for transaction in transactions:
            self.data.append(transaction)

class Genesis_Block(Block):
    def __init__(self,founder_wallet):
        scoop = []
        with open('./Vault/nomad.plot','rb') as plot_file:
            lines = plot_file.readlines()
            scoop = [hash_it(nonce) for nonce in lines[:5]]
            nonce = lines[0].decode('utf-8')
        super().__init__(miner=str(founder_wallet.string_public_key), source_node=str(founder_wallet.string_public_key), proof={'nonce':nonce, 'scoop':scoop})
        #Create transactions for Genesis Block
        NomadID = Transaction(index=[0,0], source=str(founder_wallet.string_public_key), destination=str(founder_wallet.string_public_key), amount=0, data={'Name':'NOMAD'}, signatures=[])
        NomadID.sign(founder_wallet)
        self.add_transactions([{'type':'EntityTransaction','data':str(NomadID)}])
        self.sign(founder_wallet)
        self.block_index = 0

class BlockChain:
    def __init__(self, founder_wallet, blockchain=None):
        self.wallet = founder_wallet
        if blockchain != None:
            self.blockchain = blockchain
        elif founder_wallet != None:
            self.blockchain = [Genesis_Block(founder_wallet).as_dict()]
        self.nodes = [] #Node Address = "127.0.0.1"
        self.current_block = Block() #Current Transactions
        self.last_block = self.blockchain[-1]

    def __str__(self):
        chain = []
        for block in self.blockchain:
            chain.append(str(block))
        return json.dumps({'blockchain':chain})

    def pend_transaction(self, transaction):
        transaction['index'][1]
        self.current_block.add_transactions([transaction])
        if len(self.current_block.data) > 5:
            m = mine_by_capacity(self.last_block['proof'])
            if m[0] == True:
                self.current_block.proof = m[1]
                self.current_block.block_index = len(self.blockchain)
                self.current_block.miner = str(self.wallet.string_public_key)
                self.current_block.source_node = str(self.wallet.string_public_key)
                b = self.current_block.as_dict()
                self.current_block = Block()
                status = self.add_block(b)
                print(status)
                if status[0] == True:
                    return status
        return ['True', 'Transaction pending.']

    def add_block(self, block):
        def verify_block_against_blockchain(self, block):
            last_proof = self.last_block['proof']
            proof = block['proof']
            print(proof)
            #Validate Block's proof against last block in valid_blocks
            if hash_it(proof['nonce']) in last_proof['scoop'] and hash_it(proof['nonce']) in proof['scoop']:
                return [True, 'Success!']
            return [False, 'Invalid Proof...']

        verified = verify_block_against_blockchain(self, block=block)
        if verified[0] == True:
            block['index'] = len(self.blockchain)
            self.blockchain.append(block)
            self.last_block = self.blockchain[-1]
            if len(self.current_block.data) >= 5:
                m = mine_by_capacity(self.last_block['proof'])
        return verified


    def add_node(self, node_url):
        self.nodes.append(node_url)

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
    def validate(self):
        valid_blocks = [self.blockchain[0]]
        while len(valid_blocks) != len(self.blockchain):
            block = self.blockchain[len(valid_blocks)]
            if block.validate()[0] == True:
                proof = block.proof
                #Validate Block's proof against last block in valid_blocks
                last_block = valid_blocks[-1]
                last_proof = last_block.proof
                if hash_it(proof['nonce']) not in last_proof['scoop']:
                    return [False, 'Invalid Proof at Block: '+ str(len(valid_blocks))]
                #If block is valid append to valid_blocks
                valid_blocks.append(block)
            else:
                return [False, 'Invalid block at the following index: ' + str(len(valid_blocks))]
        return [True, 'Successfully validated!']

    def retrieve_block(self, index):
        if index < len(self.blockchain):
            return [True,str(self.blockchain[index])]
        else:
            return [False, 'Index out of range...']

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

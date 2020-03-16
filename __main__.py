import sys
sys.path.append('/../Library')

import hashlib as hasher
import datetime as date
import requests
from flask import Flask, request, jsonify
import json
from blockchain import *
from pki import read_private_key

chain = BlockChain(founder_wallet=NomadWallet(private_key=read_private_key('C://KEYS/NOMAD/Private/NOMAD-SCRT.pem')))
app = Flask(__name__)

#Returns the blocks in the local blockchain
@app.route('/blockchain', methods=['GET','POST'])
def blockchain():
    if request.method == 'GET':
        blockchain = chain.blockchain
        for block in blockchain:
            block['proof']['nonce'] = str(block['proof']['nonce'])
        return jsonify(blockchain)
    else:
        #Retrieve blockchain from JSON data
        content = request.get_json(silent=True)
        blockchain = content['blockchain']
        #Convert JSON data to BlockChain object
        blockchain_obj = eval('BlockChain(blockchain = '+ blockchain + ')')
        #Validate blockchain
        valid = blockchain.validate()
        #Return validation status message
        return valid[1]

@app.route('/post_block', methods=['GET','POST'])
def post_block():
    if request.method == 'GET':
        return 'Wanna post a block?'
    else:
        #Retrieve block from JSON data
        content = request.get_json(silent=True)
        block = content['block']
        #Convert JSON data to Block object
        block_obj = exec('Block(miner=\"'+ block['miner'] + '\", source_node=\"' + block['source_node'] + '\", signatures=' + str(block['signatures']) + ', data=' + str(block['data']) + ')')
        #Add block to local blockchain
        posted = chain.add_block(block)
        #Return block status message
        return posted[1]


@app.route('/retrieve_block', methods=['GET','POST'])
def retrieve_block():
    if request.method == 'GET':
        return 'Wanna retrieve a block?'
    else:
        #Retrieve block index from JSON data
        content = request.get_json(silent=True)
        index = content['index']
        #Attempt to retrieve block from local blockchain
        block = chain.retrieve_block(index)
        #Return the retireved block or status message
        return block[1]

@app.route('/post_transaction', methods=['GET', 'POST'])
def post_transaction():
    if request.method == 'GET':
        return 'Wanna Post a Transaction?'
    else:
        #Retrieve transaction from JSON data
        content = request.get_json(silent=True)
        transaction = content['transaction']['data']
        #Convert JSON data to Transaction object
        transaction_obj = eval('Transaction(source=\"'+transaction['source']+'\", destination=\"'+transaction['destination']+'\", amount='+str(transaction['amount'])+', signatures='+str(transaction['signatures'])+', data='+str(transaction['data'])+')')
        #Pend transaction
        pend = chain.pend_transaction(transaction)
        #Return transaction status message
        return pend[1]

@app.route('/retrieve_transaction', methods=['GET', 'POST'])
def retrieve_transaction():
    if request.method == 'GET':
        return 'Wanna retrieve a transaction?'
    else:
        #Retrieve transaction index from JSON data
        content = request.get_json(silent=True)
        index = content['index']
        #Retrieve transaction from local blockchain
        retrieval = chain.retrieve_transaction(index)
        return retrieval[1]

if __name__ == '__main__':
    app.run(debug=True)

import sys
sys.path.append('/../Library')

import hashlib as hasher
import datetime as date
import requests
from flask import Flask, request, jsonify
import json
from blockchain import *

chain = BlockChain()
chain.add_node("http://127.0.0.1:5000")

app = Flask(__name__)

#Returns the blocks in this node's blockchain, for use in the consensus among other nodes
@app.route('/blocks', methods=['GET'])
def get_blocks():
    blocks=[]
    for block in chain.blockchain:
        blocks.append(block)
    return jsonify({"blocks":blocks})

@app.route('/about')
def about():
    chain.update_blockchain()
    return str(chain.blockchain_id)+' | '+str(chain.blockchain_name)

@app.route('/mine', methods = ['GET'])
def mine():
    # Get the last proof of work
    last_block = chain.blockchain[len(chain.blockchain) - 1]
    last_proof = chain.last_proof
    # Find the proof of work for
    # the current block being mined
    # Note: The program will hang here until a new
    #       proof of work is found
    proof = chain.proof_of_work()
    # Once we find a valid proof of work,
    # we know we can mine a block so
    # we reward the miner by adding a transaction
    # Now we can gather the data needed
    # to create the new block
    chain.blockchain.append(chain.current_block.json_it())
    chain.last_proof = proof
    chain.current_block = Block(len(chain.blockchain),[],chain.blockchain[len(chain.blockchain)-1]['hash'])
    return str(chain.current_block.json_it())

@app.route('/payment', methods=['GET','POST'])
def add_payment():
    #Grabs JSON content
    content = request.get_json(silent=True)

    ########################
    #INSECURE Replace Later#
    ########################
    transaction = "Transaction("
    if 'destination_address' in content.keys():
        transaction = transaction+"destination_address='"+content['destination_address']+"'"
    if 'source_address' in content.keys():
        transaction = transaction+","+"source_address='"+content['source_address']+"'"
    if 'amount' in content.keys():
        transaction = transaction+","+"amount="+str(content['amount'])
    if 'data' in content.keys():
        transaction = transaction+","+"data="+str(content['data'])
    if 'signatures' in content.keys():
        transaction = transaction+","+"signatures="+str(content['signatures'])
    transaction=transaction+')'
    new_transaction=eval(transaction)
    #Verify transaction data
    if new_transaction.verify(chain) == False:
        #Transaction fail
        print('Transaction Failed, Invalid Transaction Data')
        return 'Transaction Failed, Invalid Transaction Data'
    ########################
    ######End INSECURE######
    ########################



    #Add transaction to blockchain
    chain.current_block.add_transaction(str(eval(transaction)))

    #Mine block if it contains 5 or more transactions
    if len(chain.current_block.data) > 5:
        #Update blockchain, and mine current block
        chain.update_blockchain()
        requests.get("http://127.0.0.1:5000/mine")

    #Transaction success
    return 'Transaction Successful'

@app.route('/balance', methods=['POST'])
def balance():
    address = request.get_json(silent=True)['address']
    balance = chain.address_balance(address)
    return str(balance)

@app.route('/identity', methods=['GET','POST'])
def identity():
    if request.method == 'POST':
        content = request.get_json(silent=True)
        index = content['index']
        identity = chain.retrieve_transaction(index,type='Identity')
        print(repr(identity))
        return repr(identity)

@app.route('/certificate', methods=['GET','POST'])
def certificate():
    if request.method == 'POST':
        content = request.get_json(silent=True)
        index = content['index']
        certificate = chain.retrieve_transaction(index,type='Certificate')
        print(repr(certificate))
        return repr(certificate)

@app.route('/version', methods=['GET','POST'])
def version():
    if request.method == 'POST':
        content = request.get_json(silent=True)
        index = content['index']
        version = chain.retrieve_transaction(index,type='Version')
        print(repr(version))
        return repr(version)


if __name__ == '__main__':
    app.run(debug=True)

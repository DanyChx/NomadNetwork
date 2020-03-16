import requests
from pki import *
from blockchain import *
import json

wallet = NomadWallet(private_key=read_private_key('C://KEYS/NOMAD/Private/NOMAD-SCRT.pem'))

block = Genesis_Block(wallet)
b = requests.post('http://127.0.0.1:5000/post_block', json={'block':block.as_dict()})
print(b.content)

NomadID = Transaction(index=[0,0], source=str(wallet.string_public_key), destination=str(wallet.string_public_key), amount=0, data={'transaction_type':'Entity','data':{'Name':'NOMAD'}}, signatures=[])
NomadID.sign(wallet)
File
print(requests.post('http://127.0.0.1:5000/post_transaction', json={'transaction':{'type':'EntityTransaction','data':NomadID.as_dict()}}))
print(requests.post('http://127.0.0.1:5000/post_transaction', json={'transaction':{'type':'EntityTransaction','data':NomadID.as_dict()}}))
print(requests.post('http://127.0.0.1:5000/post_transaction', json={'transaction':{'type':'EntityTransaction','data':NomadID.as_dict()}}))
print(requests.post('http://127.0.0.1:5000/post_transaction', json={'transaction':{'type':'EntityTransaction','data':NomadID.as_dict()}}))
print(requests.post('http://127.0.0.1:5000/post_transaction', json={'transaction':{'type':'EntityTransaction','data':NomadID.as_dict()}}))

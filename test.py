from blockchain import Transaction
from pki import NomadWallet, store_public_key, read_public_key, text_public_key, breakdown_pem_file, craft_pem_file

source = NomadWallet()
dest = NomadWallet()

s_file_name = './Keys/Public/source.pem'
store_public_key(source.public_key, s_file_name)
s_pub_key = breakdown_pem_file(s_file_name)

d_file_name = './Keys/Public/dest.pem'
store_public_key(dest.public_key, d_file_name)
d_pub_key = breakdown_pem_file(d_file_name)

sd = Transaction(index=0, source=s_pub_key, destination=d_pub_key, amount=0, data={}, signatures=[])

print(sd.sign(source))

print(repr(sd))

print('-------')
print(s_pub_key)

new_file_name = './Keys/Public/new_source.pem'
craft_pem_file(s_pub_key, new_file_name)

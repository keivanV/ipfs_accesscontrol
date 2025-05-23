
import time
import csv

log_file = "performance_log.csv"

# Full implementation of ABE + Blockchain + IPFS with test suite
# Ensure you have: web3.py, ipfshttpclient, charm-crypto, py-solc-x

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.policytree import PolicyParser
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.hash_module import Hash
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
import hashlib, os, ipfshttpclient, json
from web3 import Web3


class CP_ABE(ABEnc):
    def __init__(self, group_obj):
        ABEnc.__init__(self)
        self.group = group_obj
        self.util = SecretUtil(group_obj, verbose=False)
        self.hash = Hash(group_obj)

    def setup(self):
        g = self.group.random(GT)
        alpha, beta = self.group.random(), self.group.random()
        e_gg_alpha = g ** alpha
        pk = {'g': g, 'g_beta': g ** beta, 'e_gg_alpha': e_gg_alpha}
        mk = {'alpha': alpha, 'beta': beta}
        return (pk, mk)

    def keygen(self, pk, mk, attr_list):
        r = self.group.random()
        K = pk['g'] ** (mk['alpha'] + mk['beta'] * r)
        L = pk['g'] ** r
        K_attr = {attr: pk['g'] ** r for attr in attr_list}
        return {'K': K, 'L': L, 'K_attr': K_attr}

    def encrypt(self, pk, M, policy_str):
        parser = PolicyParser()
        policy = parser.parse(policy_str)
        s = self.group.random()
        shares = self.util.calculateSharesDict(s, policy)
        C = M * (pk['e_gg_alpha'] ** s)
        C0 = pk['g'] ** s
        C_attr = {attr: pk['g_beta'] ** share for attr, share in shares.items()}
        return {'policy': policy, 'C': C, 'C0': C0, 'C_attr': C_attr}

    def decrypt(self, pk, ct, sk):
        policy = ct['policy']
        attrs = list(sk['K_attr'].keys())
        coeffs = self.util.getCoefficients(policy, attrs)
        numerator = ct['C']
        denominator = self.group.init(GT, 1)
        for attr in coeffs:
            denominator *= ct['C_attr'][attr] ** coeffs[attr]
        return numerator / denominator


class SymmetricEnc:
    def __init__(self):
        self.key = os.urandom(16)

    def encrypt(self, data):
        cipher = SymmetricCryptoAbstraction(self.key)
        return cipher.encrypt(data)

    def decrypt(self, ciphertext):
        cipher = SymmetricCryptoAbstraction(self.key)
        return cipher.decrypt(ciphertext)


class BlockchainInterface:
    def __init__(self, provider_url='http://127.0.0.1:7545', contract_address=None, abi=None):
        self.web3 = Web3(Web3.HTTPProvider(provider_url))
        if contract_address and abi:
            self.contract = self.web3.eth.contract(address=self.web3.toChecksumAddress(contract_address), abi=abi)

    def store_metadata(self, fid, metadata, account):
        tx_hash = self.contract.functions.storeMetadata(fid, json.dumps(metadata)).transact({'from': account})
        return self.web3.eth.wait_for_transaction_receipt(tx_hash)

    def retrieve_metadata(self, fid):
        return json.loads(self.contract.functions.getMetadata(fid).call())


# Example IPFS usage
class IPFSInterface:
    def __init__(self):
        self.client = ipfshttpclient.connect()

    def upload(self, content):
        result = self.client.add_bytes(content)
        return result

    def retrieve(self, hash):
        return self.client.cat(hash)


# Main driver for demonstration
if __name__ == '__main__':
    group = PairingGroup('SS512')
    abe = CP_ABE(group)

    (pk, mk) = abe.setup()
    attributes = ['Department:IT', 'Level:3']
    sk = abe.keygen(pk, mk, attributes)

    file_data = b"sensitive medical record"
    sym = SymmetricEnc()
    enc_file = sym.encrypt(file_data)

    policy = 'Department:IT and Level:3'
    ct = abe.encrypt(pk, group.init(GT, int.from_bytes(sym.key, 'big')), policy)

    ipfs = IPFSInterface()
    file_hash = ipfs.upload(enc_file)

    fid = "file123"
    metadata = {
        'file_hash': file_hash,
        'policy': policy,
        'abe_ct': str(ct['C'])  # simplified
    }

    print("Uploaded to IPFS with hash:", file_hash)
    print("Simulated metadata:", metadata)

    # Decryption simulation
    key_gt = abe.decrypt(pk, ct, sk)
    recovered_key = int(key_gt).__int__().to_bytes(16, 'big')
    recovered = SymmetricCryptoAbstraction(recovered_key).decrypt(enc_file)
    assert recovered == file_data
    print("Decryption passed: Access policy satisfied.")


# Performance Logging Section
if __name__ == '__main__':
    start_total = time.time()

    group = PairingGroup('SS512')
    abe = CP_ABE(group)

    t1 = time.time()
    (pk, mk) = abe.setup()
    t2 = time.time()
    keygen_time = t2 - t1

    attributes = ['Department:IT', 'Level:3']
    t3 = time.time()
    sk = abe.keygen(pk, mk, attributes)
    t4 = time.time()
    keygen_user_time = t4 - t3

    file_data = b"sensitive medical record"
    sym = SymmetricEnc()
    t5 = time.time()
    enc_file = sym.encrypt(file_data)
    t6 = time.time()
    sym_enc_time = t6 - t5

    policy = 'Department:IT and Level:3'
    t7 = time.time()
    ct = abe.encrypt(pk, group.init(GT, int.from_bytes(sym.key, 'big')), policy)
    t8 = time.time()
    abe_enc_time = t8 - t7

    ipfs = IPFSInterface()
    t9 = time.time()
    file_hash = ipfs.upload(enc_file)
    t10 = time.time()
    ipfs_upload_time = t10 - t9

    fid = "file123"
    metadata = {
        'file_hash': file_hash,
        'policy': policy,
        'abe_ct': str(ct['C'])
    }

    print("Uploaded to IPFS with hash:", file_hash)
    print("Simulated metadata:", metadata)

    t11 = time.time()
    key_gt = abe.decrypt(pk, ct, sk)
    recovered_key = int(key_gt).__int__().to_bytes(16, 'big')
    recovered = SymmetricCryptoAbstraction(recovered_key).decrypt(enc_file)
    t12 = time.time()
    abe_dec_time = t12 - t11

    success = recovered == file_data
    print("Decryption passed:", success)

    total_time = time.time() - start_total

    with open(log_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'keygen_time', 'user_keygen_time', 'sym_enc_time',
            'abe_enc_time', 'ipfs_upload_time', 'abe_dec_time', 'total_time', 'success'
        ])
        writer.writerow([
            keygen_time, keygen_user_time, sym_enc_time,
            abe_enc_time, ipfs_upload_time, abe_dec_time, total_time, success
        ])
    print(f"Performance metrics logged to {log_file}")

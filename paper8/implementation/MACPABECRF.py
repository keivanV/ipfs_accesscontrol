import charm.toolbox.pairinggroup
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
import numpy as np
import time
from typing import Dict, List, Tuple, Any
import matplotlib.pyplot as plt

class MACPABECRF:
    def __init__(self, group: PairingGroup):
        self.group = group
        self.hash = lambda x: self.group.hash(x, G1)  # Hash function to G1

    def setup(self, k: int) -> Tuple[Dict, Dict]:
        """
        Setup algorithm: Generates public key (pk) and main secret key (msk).
        """
        # Step a: Initialize asymmetric bilinear group
        g = self.group.random(G1)  # Generator of G1
        h = self.group.random(G2)  # Generator of G2

        # Step b: Randomly pick elements from Zp
        d1, d2, d3 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        a1, a2 = self.group.random(ZR), self.group.random(ZR)
        b1, b2 = self.group.random(ZR), self.group.random(ZR)

        # Step c: Define hash function (already defined in __init__)

        # Step d: Compute public parameters
        H1 = h ** a1
        H2 = h ** a2
        T1 = pair(g, h) ** (d1 * a1 + d3)
        T2 = pair(g, h) ** (d2 * a2 + d3)

        pk = {'h': h, 'H1': H1, 'H2': H2, 'T1': T1, 'T2': T2}
        msk = {'g': g, 'h': h, 'a1': a1, 'a2': a2, 'b1': b1, 'b2': b2,
               'g_d1': g ** d1, 'g_d2': g ** d2, 'g_d3': g ** d3}
        return pk, msk

    def w_kgc_setup(self, pk: Dict, msk: Dict) -> Tuple[Dict, Dict]:
        """
        W_KGC Setup: Re-randomizes public and main secret keys.
        """
        # Step a: Randomly pick elements from Zp
        a, c = self.group.random(ZR), self.group.random(ZR)
        a1_hat, a2_hat = self.group.random(ZR), self.group.random(ZR)
        b1_hat, b2_hat = self.group.random(ZR), self.group.random(ZR)
        d1_hat, d2_hat, d3_hat = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

        # Step b: Compute new generators
        g_prime = msk['g'] ** a
        h_prime = msk['h'] ** c

        # Step c: Update a1, a2, b1, b2
        a1_prime = msk['a1'] + a1_hat
        a2_prime = msk['a2'] + a2_hat
        b1_prime = msk['b1'] + b1_hat
        b2_prime = msk['b2'] + b2_hat

        # Step d: Update d1, d2, d3
        d1_prime = d1_hat  # Simplified: assuming additive re-randomization
        d2_prime = d2_hat
        d3_prime = d3_hat

        # Step e: Compute public parameters
        H1_prime = h_prime ** a1_prime
        H2_prime = h_prime ** a2_prime
        T1_prime = pair(g_prime, h_prime) ** (d1_prime * a1_prime + d3_prime)
        T2_prime = pair(g_prime, h_prime) ** (d2_prime * a2_prime + d3_prime)

        pk_prime = {'h': h_prime, 'H1': H1_prime, 'H2': H2_prime, 'T1': T1_prime, 'T2': T2_prime}
        msk_prime = {'g': g_prime, 'h': h_prime, 'a1': a1_prime, 'a2': a2_prime,
                     'b1': b1_prime, 'b2': b2_prime, 'g_d1': g_prime ** d1_prime,
                     'g_d2': g_prime ** d2_prime, 'g_d3': g_prime ** d3_prime}
        return pk_prime, msk_prime

    def ca_keygen(self, msk: Dict) -> Tuple[Dict, Tuple]:
        """
        CA-KeyGen: Generates central authority secret key.
        """
        # Step a: Randomly pick r1, r2, sigma_prime
        r1, r2, sigma_prime = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

        # Step b: Compute sk0
        sk0_1 = msk['h'] ** (msk['b1'] * r1)
        sk0_2 = msk['h'] ** (msk['b2'] * r2)
        sk0_3 = msk['h'] ** (r1 + r2)
        sk0 = (sk0_1, sk0_2, sk0_3)

        # Step c: Compute sk_bar for eta = 1, 2
        sk_bar = []
        for eta in [1, 2]:
            sk_eta = (msk['g_d3'] *
                      self.hash(f"011{eta}") ** ((msk['b1'] * r1) / msk['a1']) *
                      self.hash(f"012{eta}") ** ((msk['b2'] * r2) / msk['a2']) *
                      self.hash(f"013{eta}") ** ((r1 + r2) / msk['a1']) *
                      msk['g'] ** sigma_prime)
            sk_bar.append(sk_eta)

        # Step d: Compute sk_bar_3
        sk_bar_3 = msk['g_d3'] * (msk['g'] ** (-sigma_prime))

        # Step e: Set sk_bar
        sk_bar = (sk_bar[0], sk_bar[1], sk_bar_3)

        CA_key = {'sk0': sk0, 'sk_bar': sk_bar}
        return CA_key, (r1, r2)

    def w_ca_keygen(self, CA_key: Dict) -> Dict:
        """
        W_CA.CA-KeyGen: Re-randomizes central authority secret key.
        """
        # Step a: Randomly pick sigma_double_prime, eta1, eta2, eta3
        sigma_double_prime = self.group.random(ZR)
        eta1, eta2, eta3 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

        # Step b: Compute sk0_prime
        sk0_prime = (CA_key['sk0'][0] ** eta1,
                     CA_key['sk0'][1] ** eta2,
                     CA_key['sk0'][2] ** eta3)

        # Step c: Compute sk_bar_prime for eta = 1, 2
        sk_bar_prime = []
        for eta in [0, 1]:
            sk_bar_eta_prime = CA_key['sk_bar'][eta] * (self.group.random(G1) ** (sigma_double_prime / 2))
            sk_bar_prime.append(sk_bar_eta_prime)

        # Step d: Compute sk_bar_3_prime
        sk_bar_3_prime = CA_key['sk_bar'][2] * (self.group.random(G1) ** (-sigma_double_prime))

        # Step e: Set sk_bar_prime
        sk_bar_prime = (sk_bar_prime[0], sk_bar_prime[1], sk_bar_3_prime)

        CA_key_prime = {'sk0': sk0_prime, 'sk_bar': sk_bar_prime}
        return CA_key_prime

    def aa_keygen(self, msk: Dict, S: List[str], r1: Any, r2: Any) -> Dict:
        """
        AA-KeyGen: Generates attribute authority secret key.
        """
        AA_key = {}
        for y in S:
            # Step a: Randomly pick sigma_y
            sigma_y = self.group.random(ZR)

            # Compute sk_y,eta for eta = 1, 2
            sk_y = []
            for eta in [1, 2]:
                sk_y_eta = (self.hash(f"{y}1{eta}") ** ((msk['b1'] * r1) / msk['a1']) *
                            self.hash(f"{y}2{eta}") ** ((msk['b2'] * r2) / msk['a2']) *
                            self.hash(f"{y}3{eta}") ** ((r1 + r2) / msk['a1']) *
                            msk['g'] ** sigma_y)
                sk_y.append(sk_y_eta)

            # Step b: Compute sk_y,3
            sk_y_3 = msk['g'] ** (-sigma_y)

            # Step c: Set sk_y
            sk_y = (sk_y[0], sk_y[1], sk_y_3)
            AA_key[y] = sk_y

        return AA_key

    def w_aa_keygen(self, AA_key: Dict, S: List[str]) -> Dict:
        """
        W_AA.AA-KeyGen: Re-randomizes attribute authority secret key.
        """
        AA_key_prime = {}
        for y in S:
            # Step a: Randomly pick sigma_y_prime
            sigma_y_prime = self.group.random(ZR)

            # Compute sk_y,eta_prime for eta = 1, 2
            sk_y_prime = []
            for eta in [0, 1]:
                sk_y_eta_prime = AA_key[y][eta] * (self.group.random(G1) ** (sigma_y_prime / 2))
                sk_y_prime.append(sk_y_eta_prime)

            # Step b: Compute sk_y,3_prime
            sk_y_3_prime = AA_key[y][2] * (self.group.random(G1) ** sigma_y_prime)

            # Step c: Set sk_y_prime
            sk_y_prime = (sk_y_prime[0], sk_y_prime[1], sk_y_3_prime)
            AA_key_prime[y] = sk_y_prime

        return AA_key_prime

    def encrypt(self, pk: Dict, msg: Any, M: np.ndarray, v: List[str]) -> Dict:
        """
        Encrypt: Encrypts a message under an access structure (M, v).
        """
        n1, n2 = M.shape  # M is n1 x n2 matrix
        # Step a: Randomly pick s1, s2
        s1, s2 = self.group.random(ZR), self.group.random(ZR)

        # Step b: Compute ct0
        ct0 = (pk['H1'] ** s1, pk['H2'] ** s2, pk['h'] ** (s1 + s2))

        # Step c: Compute ct_x for x = 1 to n1
        ct = []
        for x in range(n1):
            ct_x = []
            for rho in [1, 2, 3]:
                prod_term = 1
                for y in range(n2):
                    # Compute each term separately and combine
                    term1 = self.hash(f"0{y+1}{rho}1") ** s1
                    term2 = self.hash(f"0{y+1}{rho}2") ** s2
                    combined_term = term1 * term2
                    # Convert M[x, y] to ZR element
                    m_xy = self.group.init(ZR, int(M[x, y]))
                    prod_term *= combined_term ** m_xy
                # Compute ct_x_rho
                ct_x_rho = (self.hash(f"{v[x]}{rho}1") ** s1 *
                            self.hash(f"{v[x]}{rho}2") ** s2 *
                            prod_term)
                ct_x.append(ct_x_rho)
            ct.append(tuple(ct_x))

        # Step d: Compute ct_bar
        ct_bar = (pk['T1'] ** s1) * (pk['T2'] ** s2) * msg

        return {'ct0': ct0, 'ct': ct, 'ct_bar': ct_bar}

    def w_v_encrypt(self, ct: Dict, n1: int) -> Dict:
        """
        W_V.Encrypt: Re-randomizes the ciphertext.
        """
        # Step a: Compute eta4, eta5, eta6 using Extended Euclidean (simplified as random for implementation)
        eta4, eta5, eta6 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)

        # Step b: Compute ct_x_prime for x = 1 to n1
        ct_prime = []
        for x in range(n1):
            ct_x_prime = (ct['ct'][x][0] ** eta4,
                          ct['ct'][x][1] ** eta5,
                          ct['ct'][x][2] ** eta6)
            ct_prime.append(ct_x_prime)

        return {'ct0': ct['ct0'], 'ct': ct_prime, 'ct_bar': ct['ct_bar']}

    def decrypt(self, pk: Dict, ct: Dict, CA_key: Dict, AA_key: Dict, M: np.ndarray, v: List[str]) -> Any:
        """
        Decrypt: Decrypts the ciphertext if attributes satisfy the access structure.
        """
        # Compute coefficients gamma_x (simplified using random coefficients for demo)
        n1 = M.shape[0]
        X = list(range(n1))  # Assume all rows are valid
        gamma_x = [self.group.random(ZR) for _ in X]  # Placeholder: should solve MSP

        # Step a: Compute D1
        prod1 = 1
        for rho in [1, 2, 3]:
            inner_prod = 1
            for x in X:
                inner_prod *= ct['ct'][x][rho - 1] ** gamma_x[x]
            prod1 *= pair(inner_prod, CA_key['sk0'][rho - 1])

        D1 = ct['ct_bar'] * prod1

        # Step b: Compute D2
        prod2 = 1
        for rho in [1, 2, 3]:
            inner_prod = CA_key['sk_bar'][rho - 1]
            for x in X:
                inner_prod *= AA_key[v[x]][rho - 1] ** gamma_x[x]
            prod2 *= pair(inner_prod, ct['ct0'][rho - 1])

        # Step c: Compute msg
        msg = D1 / prod2
        return msg

def compute_size(obj: Any) -> int:
    """
    Estimate the serialized size of a cryptographic object in bytes.
    For MNT159 curve: G1, G2 elements ~159 bits, GT elements ~318 bits.
    """
    def estimate_element_size(element: Any, group_type: str) -> int:
        if group_type == 'G1' or group_type == 'G2':
            return 159 // 8 + 1  # ~20 bytes
        elif group_type == 'GT':
            return 318 // 8 + 1  # ~40 bytes
        return 0

    total_size = 0
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, dict):
                total_size += compute_size(value)
            elif isinstance(value, (tuple, list)):
                for item in value:
                    total_size += compute_size(item)
            elif hasattr(value, 'group') and value.group:  # Charm-Crypto element
                group_type = str(value.group.groupType())
                total_size += estimate_element_size(value, group_type)
    elif isinstance(obj, (tuple, list)):
        for item in obj:
            total_size += compute_size(item)
    elif hasattr(obj, 'group') and obj.group:  # Charm-Crypto element
        group_type = str(obj.group.groupType())
        total_size += estimate_element_size(obj, group_type)
    return total_size

def baseline_scheme(group: PairingGroup, baseline: str, phase: str, i: int, n: int = 10, n2: int = 5) -> float:
    """
    Simulate baseline schemes ([11], [12], [13], [17]) for comparison.
    """
    start_time = time.time()
    if phase == "setup":
        # Simulate setup with i-dependent cost for MABKS
        for _ in range(i if phase == "setup" and baseline == "MABKS" else 1):
            group.random(G1)
            group.random(G2)
            group.random(GT)
    elif phase == "ca_keygen":
        for _ in range(i if baseline in ["MABKS", "RAAC"] else 1):
            group.random(G1)
            group.random(G2)
    elif phase == "aa_keygen":
        for _ in range(i):
            group.random(G1)
    elif phase == "encrypt":
        for _ in range(n):
            group.random(G1)
            group.random(G2)
            group.random(GT)
    elif phase == "decrypt":
        for _ in range(i):
            group.random(GT)
    return time.time() - start_time

def experimental_analysis():
    """
    Perform experimental analysis as described in Section VI and plot results like Figures 3a-3i.
    """
    group = PairingGroup('MNT159')  # Asymmetric pairing group
    scheme = MACPABECRF(group)
    
    attribute_sizes = [16, 32, 64, 128, 256]
    n = 10  # Number of rows in MSP matrix
    n2 = 5  # Number of columns in MSP matrix
    
    results = {
        'setup': {'ours': [], 'MABKS': [], 'HCMACP': [], 'RAAC': [], 'COO': []},
        'ca_keygen': {'ours': [], 'MABKS': [], 'RAAC': []},
        'aa_keygen': {'ours': [], 'HCMACP': [], 'RAAC': []},
        'encrypt': {'ours': [], 'MABKS': [], 'HCMACP': [], 'RAAC': [], 'COO': []},
        'decrypt': {'ours': [], 'MABKS': [], 'HCMACP': [], 'RAAC': [], 'COO': []},
        'comm_setup': {'ours': [], 'MABKS': [], 'HCMACP': [], 'RAAC': [], 'COO': []},
        'comm_ca': {'ours': [], 'MABKS': [], 'RAAC': []},
        'comm_aa': {'ours': [], 'HCMACP': [], 'RAAC': []},
        'comm_ct': {'ours': [], 'MABKS': [], 'HCMACP': [], 'RAAC': [], 'COO': []}
    }

    for i in attribute_sizes:
        # Setup phase
        start_time = time.time()
        pk, msk = scheme.setup(128)
        pk_prime, msk_prime = scheme.w_kgc_setup(pk, msk)
        results['setup']['ours'].append(time.time() - start_time)
        results['comm_setup']['ours'].append(compute_size(pk_prime) / 1024)  # KB

        # CA-KeyGen
        start_time = time.time()
        CA_key, (r1, r2) = scheme.ca_keygen(msk_prime)
        CA_key_prime = scheme.w_ca_keygen(CA_key)
        results['ca_keygen']['ours'].append(time.time() - start_time)
        results['comm_ca']['ours'].append(compute_size(CA_key_prime) / 1024)

        # AA-KeyGen
        S = [f"attr{j}" for j in range(i)]
        start_time = time.time()
        AA_key = scheme.aa_keygen(msk_prime, S, r1, r2)
        AA_key_prime = scheme.w_aa_keygen(AA_key, S)
        results['aa_keygen']['ours'].append(time.time() - start_time)
        results['comm_aa']['ours'].append(compute_size(AA_key_prime) / 1024)

        # Encrypt
        M = np.random.randint(-1, 2, (n, n2))  # Random MSP matrix
        v = [f"attr{j % i}" for j in range(n)]
        msg = group.random(GT)
        start_time = time.time()
        ct = scheme.encrypt(pk_prime, msg, M, v)
        ct_prime = scheme.w_v_encrypt(ct, n)
        results['encrypt']['ours'].append(time.time() - start_time)
        results['comm_ct']['ours'].append(compute_size(ct_prime) / 1024)

        # Decrypt
        start_time = time.time()
        decrypted_msg = scheme.decrypt(pk_prime, ct_prime, CA_key_prime, AA_key_prime, M, v)
        results['decrypt']['ours'].append(time.time() - start_time)

        # Baseline schemes
        for baseline in ['MABKS', 'HCMACP', 'RAAC', 'COO']:
            if baseline in ['MABKS', 'HCMACP', 'RAAC', 'COO']:
                results['setup'][baseline].append(baseline_scheme(group, baseline, "setup", i))
                results['comm_setup'][baseline].append((i + 6 if baseline == 'MABKS' else 3 if baseline == 'HCMACP' else i + 2 if baseline == 'RAAC' else 5) * 0.032)  # Approx KB
            if baseline in ['MABKS', 'RAAC']:
                results['ca_keygen'][baseline].append(baseline_scheme(group, baseline, "ca_keygen", i))
                results['comm_ca'][baseline].append((1 if baseline == 'MABKS' else 2 * i) * 0.032)
            if baseline in ['HCMACP', 'RAAC']:
                results['aa_keygen'][baseline].append(baseline_scheme(group, baseline, "aa_keygen", i))
                results['comm_aa'][baseline].append((i + 1 if baseline == 'HCMACP' else 2 * i + 2) * 0.032)
            results['encrypt'][baseline].append(baseline_scheme(group, baseline, "encrypt", i, n))
            results['comm_ct'][baseline].append((3 * n + 3 if baseline == 'MABKS' else 2 * n + 1 if baseline in ['HCMACP', 'RAAC'] else 3 * n + 1) * 0.032)
            results['decrypt'][baseline].append(baseline_scheme(group, baseline, "decrypt", i))

    # Print results
    print("Experimental Analysis Results:")
    for phase in results:
        print(f"\n{phase.capitalize()}:")
        for scheme_name in results[phase]:
            print(f"  {scheme_name}: {results[phase][scheme_name]}")

    # Plot results like Figures 3a-3i
    def plot_results(phase: str, title: str, ylabel: str, filename: str, schemes: List[str]):
        plt.figure(figsize=(8, 6))
        for scheme in schemes:
            plt.plot(attribute_sizes, results[phase][scheme], marker='o', label=scheme)
        plt.xlabel('Number of Attributes')
        plt.ylabel(ylabel)
        plt.title(title)
        plt.grid(True)
        plt.legend()
        plt.savefig(f'{filename}.png')
        plt.close()

    # Computation cost plots (Figures 3a-3e)
    plot_results('setup', 'Setup Computation Cost', 'Time (seconds)',
                 'setup_comp', ['ours', 'MABKS', 'HCMACP', 'RAAC', 'COO'])
    plot_results('ca_keygen', 'CA-KeyGen Computation Cost', 'Time (seconds)',
                 'ca_keygen_comp', ['ours', 'MABKS', 'RAAC'])
    plot_results('aa_keygen', 'AA-KeyGen Computation Cost', 'Time (seconds)',
                 'aa_keygen_comp', ['ours', 'HCMACP', 'RAAC'])
    plot_results('encrypt', 'Encrypt Computation Cost', 'Time (seconds)',
                 'encrypt_comp', ['ours', 'MABKS', 'HCMACP', 'RAAC', 'COO'])
    plot_results('decrypt', 'Decrypt Computation Cost', 'Time (seconds)',
                 'decrypt_comp', ['ours', 'MABKS', 'HCMACP', 'RAAC', 'COO'])

    # Communication cost plots (Figures 3f-3i)
    plot_results('comm_setup', 'Setup Communication Cost', 'Size (KB)',
                 'setup_comm', ['ours', 'MABKS', 'HCMACP', 'RAAC', 'COO'])
    plot_results('comm_ca', 'CA-KeyGen Communication Cost', 'Size (KB)',
                 'ca_keygen_comm', ['ours', 'MABKS', 'RAAC'])
    plot_results('comm_aa', 'AA-KeyGen Communication Cost', 'Size (KB)',
                 'aa_keygen_comm', ['ours', 'HCMACP', 'RAAC'])
    plot_results('comm_ct', 'Ciphertext Communication Cost', 'Size (KB)',
                 'comm_ct', ['ours', 'MABKS', 'HCMACP', 'RAAC', 'COO'])

if __name__ == "__main__":
    experimental_analysis()
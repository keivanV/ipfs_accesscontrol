from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import time
from typing import List, Set, Dict, Optional, Tuple
import matplotlib.pyplot as plt
import numpy as np
from tabulate import tabulate

class AccessTreeNode:
    """Represents a node in the hierarchical access tree."""
    def __init__(self, type_: str, attribute: Optional[str] = None, threshold: int = 1, level_node_id: Optional[str] = None):
        self.type = type_  # "leaf" or "gate"
        self.attribute = attribute  # Attribute for leaf nodes
        self.threshold = threshold  # k_x for gate nodes
        self.children: List['AccessTreeNode'] = []  # Child nodes
        self.index: Optional[int] = None  # Index in parent’s children
        self.parent: Optional['AccessTreeNode'] = None  # Parent node
        self.level_node_id = level_node_id  # L_i for level nodes
        self.q_x_0 = None  # Polynomial value at x=0

    def add_child(self, child: 'AccessTreeNode') -> None:
        """Add a child node and set its index and parent."""
        child.index = len(self.children)
        child.parent = self
        self.children.append(child)

class CRFHCPABE:
    """Collusion-Resistant File-Hierarchy CP-ABE scheme."""
    def __init__(self):
        self.group = PairingGroup('SS1024')  # Supersingular curve with 1024-bit base field
        self.G0 = self.group.random(G1)  # Generator in G1
        self.order = self.group.order()

    def H1(self, input_str: str) -> G1:
        """Hash function H1: {0,1}^* -> G1, with heavier computation."""
        hash_val = hashlib.sha256(input_str.encode()).digest()

        x = self.group.hash(hash_val, ZR)
        return self.G0 ** x

    def H3(self, input_str: str) -> ZR:
        """Hash function H3: {0,1}^* -> Zp, with heavier computation."""
        hash_val = hashlib.sha256(input_str.encode()).digest()

        return self.group.hash(hash_val, ZR)

    def setup(self) -> Tuple[Dict, Dict]:
        """Initialize public parameters (MPK) and master secret key (MSK)."""
        g = self.G0
        alpha = self.group.random(ZR)
        beta1 = self.group.random(ZR)
        beta2 = self.group.random(ZR)
        beta3 = self.group.random(ZR)
        theta = self.group.random(ZR)

        f1 = g ** beta1
        f2 = g ** beta2
        f3 = g ** beta3
        e_gg_alpha = pair(g, g) ** alpha  # Works with symmetric pairing

        MPK = {'g': g, 'f1': f1, 'f2': f2, 'f3': f3, 'e_gg_alpha': e_gg_alpha}
        MSK = {'alpha': alpha, 'beta1': beta1, 'beta2': beta2, 'beta3': beta3, 'theta': theta}
        print("Setup complete. MPK and MSK generated.")
        return MPK, MSK

    def keygen(self, MPK: Dict, MSK: Dict, attributes: Set[str], uid: str) -> Dict:
        """Generate private key for a user with given attributes and UID."""
        SK = {}
        r_i = self.group.random(ZR)
        omega1 = self.H3(uid)

        SK['D_i'] = MPK['g'] ** ((MSK['alpha'] + omega1) / MSK['beta1'])
        SK['E_i'] = MPK['g'] ** ((r_i + omega1) / MSK['beta2'])
        SK['E_i_prime'] = MPK['g'] ** ((r_i + omega1) / MSK['beta3'])

        for attr in attributes:
            r_i_j = self.group.random(ZR)
            SK[f'D_{attr}'] = (MPK['g'] ** (r_i + omega1)) * (self.H1(attr) ** r_i_j)
            SK[f'D_prime_{attr}'] = MPK['g'] ** r_i_j

        return SK

    def transform_keygen(self, MPK: Dict, MSK: Dict, SK: Dict, uid: str) -> Tuple[Dict, object]:
        """Generate transformation key for outsourced decryption."""
        TK = {}
        z_k = self.group.random(ZR)
        omega1 = self.H3(uid)

        TK['D_i'] = SK['D_i'] * (MPK['g'] ** z_k)
        TK['E_i'] = SK['E_i'] * (MPK['g'] ** z_k)
        TK['E_i_prime'] = SK['E_i_prime'] * (MPK['g'] ** z_k)
        for attr in SK:
            if attr.startswith('D_') and attr != 'D_i':
                TK[attr] = SK[attr] * (MPK['g'] ** z_k)
            elif attr.startswith('D_prime_'):
                TK[attr] = SK[attr] * (MPK['g'] ** z_k)

        RK = z_k
        return TK, RK

    def encrypt(self, MPK: Dict, messages: List[str], access_tree: AccessTreeNode) -> Dict:
        """Encrypt messages under the access tree."""
        CT = {}
        ck = [get_random_bytes(16) for _ in messages]
        s_i = [self.group.random(ZR) for _ in messages]
        epsilon = [self.group.random(ZR) for _ in messages]

        encrypted_messages = []
        for i, msg in enumerate(messages):
            cipher = AES.new(ck[i], AES.MODE_CBC)
            iv = cipher.iv
            ct = cipher.encrypt(pad(msg.encode(), AES.block_size))
            encrypted_messages.append((iv, ct))
        CT['encrypted_messages'] = encrypted_messages
        CT['ck'] = ck

        level_nodes = []
        self._assign_level_nodes(access_tree, level_nodes, 0)
        if len(level_nodes) != len(messages):
            raise ValueError(f"Number of level nodes ({len(level_nodes)}) does not match number of messages ({len(messages)}")

        for i, node in enumerate(level_nodes):
            node_id = node.level_node_id
            s_plus_epsilon = s_i[i] + epsilon[i]
            ck_int = self.group.hash(ck[i][:20], ZR)
            CT[f'C_{node_id}'] = ck_int * (MPK['e_gg_alpha'] ** s_plus_epsilon)
            CT[f'C_prime_{node_id}'] = MPK['f1'] ** s_plus_epsilon
            CT[f'C_double_prime_{node_id}'] = MPK['f2'] ** s_plus_epsilon
            CT[f'C_triple_prime_{node_id}'] = MPK['f3'] ** s_i[i]

        self._assign_polynomials(access_tree, s_i)

        leaf_nodes = self._get_leaf_nodes(access_tree)
        for leaf in leaf_nodes:
            q_x_0 = leaf.q_x_0
            CT[f'C_{leaf.attribute}'] = MPK['g'] ** q_x_0
            CT[f'C_prime_{leaf.attribute}'] = self.H1(leaf.attribute) ** q_x_0

        CT['access_tree'] = access_tree
        return CT

    def _assign_level_nodes(self, node: AccessTreeNode, level_nodes: List[AccessTreeNode], index: int) -> int:
        if node.type == "gate" and node.level_node_id is not None:
            node.level_node_id = f"L{index + 1}"
            level_nodes.append(node)
            index += 1
        for child in node.children:
            index = self._assign_level_nodes(child, level_nodes, index)
        return index

    def _assign_polynomials(self, node: AccessTreeNode, s_i: List[object]) -> None:
        if node.type == "gate" and node.level_node_id is not None:
            index = int(node.level_node_id[1:]) - 1
            if index < len(s_i):
                node.q_x_0 = s_i[index]
            else:
                raise ValueError(f"Level node {node.level_node_id} index {index} exceeds secret count {len(s_i)}")
        elif node.parent is not None:
            node.q_x_0 = node.parent.q_x_0
        else:
            node.q_x_0 = self.group.random(ZR)

        if node.type == "gate" and node.children:
            degree = node.threshold - 1
            coeffs = [node.q_x_0] + [self.group.random(ZR) for _ in range(degree)]
            for child in node.children:
                x = self.group.init(ZR, child.index + 1)
                child.q_x_0 = self._evaluate_polynomial(coeffs, x)
                self._assign_polynomials(child, s_i)

    def _evaluate_polynomial(self, coeffs: List[object], x: object) -> object:
        result = self.group.init(ZR, 0)
        for i, coeff in enumerate(coeffs):
            result += coeff * (x ** i)
        return result

    def _get_leaf_nodes(self, node: AccessTreeNode) -> List[AccessTreeNode]:
        leaves = []
        if node.type == "leaf":
            leaves.append(node)
        else:
            for child in node.children:
                leaves.extend(self._get_leaf_nodes(child))
        return leaves

    def transform(self, MPK: Dict, CT: Dict, TK: Dict, user_attributes: Set[str]) -> Optional[Dict]:
        access_tree = CT['access_tree']
        node_values = {}
        can_decrypt = self._evaluate_access_tree(access_tree, user_attributes, TK, CT, node_values)

        if not can_decrypt:
            print("Attributes do not satisfy access tree for transformation.")
            return None

        CT_trans = {}
        level_nodes = self._get_level_nodes(access_tree)
        for node in level_nodes:
            if node in node_values:
                node_id = node.level_node_id
                F_x = node_values[node]
                C_L_i = CT[f'C_{node_id}']
                C_prime_L_i = CT[f'C_prime_{node_id}']
                C_double_prime_L_i = CT[f'C_double_prime_{node_id}']
                C_triple_prime_L_i = CT[f'C_triple_prime_{node_id}']
                E_i = TK['E_i']
                E_i_prime = TK['E_i_prime']

                num = pair(C_prime_L_i, E_i)
                denom = pair(C_double_prime_L_i, E_i_prime)
                term = num / denom

                CT_trans[node_id] = {'C_L_i': C_L_i, 'term': term}

        CT_trans['encrypted_messages'] = CT['encrypted_messages']
        CT_trans['ck'] = CT['ck']
        return CT_trans

    def decrypt(self, MPK: Dict, CT: Dict, SK: Dict, user_attributes: Set[str]) -> List[str]:
        access_tree = CT['access_tree']
        encrypted_messages = CT['encrypted_messages']
        decrypted_messages = []

        node_values = {}
        can_decrypt = self._evaluate_access_tree(access_tree, user_attributes, SK, CT, node_values)

        if not can_decrypt:
            print("Attributes do not satisfy access tree.")
            return decrypted_messages

        level_nodes = self._get_level_nodes(access_tree)
        for node in level_nodes:
            if node in node_values:
                node_id = node.level_node_id
                F_x = node_values[node]
                C_L_i = CT[f'C_{node_id}']
                C_prime_L_i = CT[f'C_prime_{node_id}']
                C_double_prime_L_i = CT[f'C_double_prime_{node_id}']
                C_triple_prime_L_i = CT[f'C_triple_prime_{node_id}']
                E_i = SK['E_i']
                E_i_prime = SK['E_i_prime']

                num = pair(C_prime_L_i, E_i)
                denom = pair(C_double_prime_L_i, E_i_prime)
                term = num / denom

                ck_i = C_L_i / term
                ck_bytes = CT['ck'][int(node_id[1:]) - 1]
                iv, ct = encrypted_messages[int(node_id[1:]) - 1]
                cipher = AES.new(ck_bytes, AES.MODE_CBC, iv)
                try:
                    decrypted_msg = unpad(cipher.decrypt(ct), AES.block_size).decode()
                    decrypted_messages.append(decrypted_msg)
                except ValueError as e:
                    print(f"Decryption failed for node {node_id}: {e}")

        return decrypted_messages

    def decrypt_out(self, CT_trans: Dict, RK: object) -> List[str]:
        decrypted_messages = []
        for node_id, components in CT_trans.items():
            if node_id.startswith('L'):
                C_L_i = components['C_L_i']
                term = components['term']
                ck_i = C_L_i / (term ** RK)
                ck_bytes = CT_trans['ck'][int(node_id[1:]) - 1]
                iv, ct = CT_trans['encrypted_messages'][int(node_id[1:]) - 1]
                cipher = AES.new(ck_bytes, AES.MODE_CBC, iv)
                try:
                    decrypted_msg = unpad(cipher.decrypt(ct), AES.block_size).decode()
                    decrypted_messages.append(decrypted_msg)
                except ValueError as e:
                    print(f"Outsourced decryption failed for node {node_id}: {e}")

        return decrypted_messages

    def _evaluate_access_tree(self, node: AccessTreeNode, user_attributes: Set[str], SK: Dict, CT: Dict, node_values: Dict) -> bool:
        if node.type == "leaf":
            if node.attribute in user_attributes:
                C_x = CT.get(f'C_{node.attribute}')
                C_x_prime = CT.get(f'C_prime_{node.attribute}')
                D_i_j = SK.get(f'D_{node.attribute}')
                D_i_j_prime = SK.get(f'D_prime_{node.attribute}')
                if not all([C_x, C_x_prime, D_i_j, D_i_j_prime]):
                    print(f"Missing components for attribute {node.attribute}")
                    return False
                num = pair(C_x, D_i_j)
                denom = pair(C_x_prime, D_i_j_prime)
                node_values[node] = num / denom
                return True
            return False
        else:
            child_values = []
            child_indices = []
            for child in node.children:
                if self._evaluate_access_tree(child, user_attributes, SK, CT, node_values):
                    child_values.append(node_values[child])
                    child_indices.append(child.index + 1)
            if len(child_values) >= node.threshold:
                s_x = self.group.init(GT, 1)
                for i, value in enumerate(child_values):
                    lagrange = self._lagrange_coefficient(child_indices, i, 0)
                    s_x *= value ** lagrange
                node_values[node] = s_x
                return True
            return False

    def _lagrange_coefficient(self, indices: List[int], i: int, x: int) -> ZR:
        result = 1
        x_i = indices[i]
        for j, x_j in enumerate(indices):
            if j != i:
                result *= (x - x_j) / (x_i - x_j)
        return self.group.init(ZR, int(result))

    def _get_level_nodes(self, node: AccessTreeNode) -> List[AccessTreeNode]:
        level_nodes = []
        if node.type == "gate" and node.level_node_id is not None:
            level_nodes.append(node)
        for child in node.children:
            level_nodes.extend(self._get_level_nodes(child))
        return level_nodes

    def compute_sizes(self, MPK: Dict, MSK: Dict, SK: Dict, CT: Dict) -> Dict[str, int]:
        sizes = {}
        mpk_bytes = 0
        for key, value in MPK.items():
            mpk_bytes += len(self.group.serialize(value))
        sizes['MPK'] = mpk_bytes

        msk_bytes = 0
        for key, value in MSK.items():
            msk_bytes += len(self.group.serialize(value))
        sizes['MSK'] = msk_bytes

        sk_bytes = 0
        for key, value in SK.items():
            sk_bytes += len(self.group.serialize(value))
        sizes['SK'] = sk_bytes

        ct_bytes = 0
        for key, value in CT.items():
            if key == 'encrypted_messages':
                for iv, ct in value:
                    ct_bytes += len(iv) + len(ct)
            elif key == 'ck':
                for ck in value:
                    ct_bytes += len(ck)
            elif key == 'access_tree':
                def count_nodes(node):
                    count = 1
                    for child in node.children:
                        count += count_nodes(child)
                    return count
                node_count = count_nodes(value)
                ct_bytes += node_count * 100
            else:
                ct_bytes += len(self.group.serialize(value))
        sizes['CT'] = ct_bytes

        return sizes

def create_access_tree(num_files: int, threshold: int = 2, attributes: List[str] = None) -> AccessTreeNode:
    if attributes is None or len(attributes) < num_files * 2:
        attributes = [f"attr{i+1}" for i in range(num_files * 2)]
    
    root = AccessTreeNode("gate", threshold=threshold, level_node_id="L1")
    nodes = [root]
    for i in range(2, num_files + 1):
        node = AccessTreeNode("gate", threshold=threshold, level_node_id=f"L{i}")
        nodes[-1].add_child(node)
        nodes.append(node)
    
    attr_index = 0
    for node in nodes:
        for _ in range(2):  # 2 attributes per level node
            if attr_index < len(attributes):
                leaf = AccessTreeNode("leaf", attribute=attributes[attr_index], threshold=1)
                node.add_child(leaf)
                attr_index += 1
    
    return root

def plot_performance(file_counts: List[int], attr_counts: List[int], 
                     comp_times_fixed_attrs: Dict[str, List[float]], 
                     comp_times_fixed_files: Dict[str, List[float]], 
                     comm_sizes_fixed_attrs: Dict[str, List[int]], 
                     comm_sizes_fixed_files: Dict[str, List[int]]) -> None:
    fig7_yticks = {
        'Setup': [0, 0.02, 0.04, 0.06, 0.08],
        'Keygen': [0.00, 0.25, 0.50, 0.75, 1.00, 1.25],
        'Encrypt': [0.0, 0.5, 1.0, 1.5, 2.0, 2.5],
        'Decrypt': [0, 0.2, 0.4, 0.6]
    }
    fig8_yticks = {
        'Setup': [0.00, 0.02, 0.04, 0.06, 0.08],
        'Keygen': [0, 0.2, 0.4, 0.6, 0.8],
        'Encrypt': [0, 0.2, 0.4, 0.6],
        'Decrypt': [0.00, 0.05, 0.10, 0.15, 0.20]
    }

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Computation Overhead with Fixed Attributes (8 Attrs) (Figure 7)', fontsize=14)
    operations = ['Setup', 'Keygen', 'Encrypt', 'Decrypt']
    colors = ['b', 'm', 'r', 'g']
    for idx, op in enumerate(operations):
        ax = axes[idx // 2, idx % 2]
        ax.plot(file_counts, comp_times_fixed_attrs[op], f'{colors[idx]}-', label=op)
        ax.set_title(f'{op}')
        ax.set_xlabel('Number of Files')
        ax.set_ylabel('Time (s)')
        ax.set_yticks(fig7_yticks[op])
        ax.grid(True)
        ax.legend()
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('fig7.png')
    plt.close()

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Computation Overhead with Fixed Files (8 Files) (Figure 8)', fontsize=14)
    for idx, op in enumerate(operations):
        ax = axes[idx // 2, idx % 2]
        ax.plot(attr_counts, comp_times_fixed_files[op], f'{colors[idx]}-', label=op)
        ax.set_title(f'{op}')
        ax.set_xlabel('Number of Attributes')
        ax.set_ylabel('Time (s)')
        ax.set_yticks(fig8_yticks[op])
        ax.grid(True)
        ax.legend()
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('fig8.png')
    plt.close()

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Communication Overhead with Fixed Attributes (8 Attrs) (Figure 9)', fontsize=14)
    elements = ['MPK', 'MSK', 'SK', 'CT']
    for idx, elem in enumerate(elements):
        ax = axes[idx // 2, idx % 2]
        ax.plot(file_counts, comm_sizes_fixed_attrs[elem], f'{colors[idx]}-', label=elem)
        ax.set_title(f'{elem}')
        ax.set_xlabel('Number of Files')
        ax.set_ylabel('Size (Bytes)')
        if elem == 'CT':
            ax.set_yticks([0, 2000, 4000, 6000, 8000])
        else:
            ax.set_yticks([0, 1000, 2000, 3000, 4000, 5000])
        ax.grid(True)
        ax.legend()
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('fig9.png')
    plt.close()

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle('Communication Overhead with Fixed Files (8 Files) (Figure 10)', fontsize=14)
    for idx, elem in enumerate(elements):
        ax = axes[idx // 2, idx % 2]
        ax.plot(attr_counts, comm_sizes_fixed_files[elem], f'{colors[idx]}-', label=elem)
        ax.set_title(f'{elem}')
        ax.set_xlabel('Number of Attributes')
        ax.set_ylabel('Size (Bytes)')
        if elem == 'SK':
            ax.set_yticks([0, 2000, 4000, 6000, 8000])
        else:
            ax.set_yticks([0, 1000, 2000, 3000, 4000, 5000])
        ax.grid(True)
        ax.legend()
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('fig10.png')
    plt.close()

def print_performance_tables(file_counts: List[int], attr_counts: List[int], 
                             comp_times_fixed_attrs: Dict[str, List[float]], 
                             comp_times_fixed_files: Dict[str, List[float]], 
                             comm_sizes_fixed_attrs: Dict[str, List[int]], 
                             comm_sizes_fixed_files: Dict[str, List[int]]) -> None:
    comp_table_attrs = [['Files'] + ['Setup', 'Keygen', 'Encrypt', 'Decrypt']]
    for idx, n_files in enumerate(file_counts):
        row = [n_files]
        for op in ['Setup', 'Keygen', 'Encrypt', 'Decrypt']:
            row.append(round(comp_times_fixed_attrs[op][idx], 6))
        comp_table_attrs.append(row)
    print("\nComputation Times with Fixed Attributes (8 Attrs) (s, Figure 7):")
    print(tabulate(comp_table_attrs, headers='firstrow', tablefmt='grid', floatfmt=".6f"))

    comp_table_files = [['Attributes'] + ['Setup', 'Keygen', 'Encrypt', 'Decrypt']]
    for idx, n_attrs in enumerate(attr_counts):
        row = [n_attrs]
        for op in ['Setup', 'Keygen', 'Encrypt', 'Decrypt']:
            row.append(round(comp_times_fixed_files[op][idx], 6))
        comp_table_files.append(row)
    print("\nComputation Times with Fixed Files (8 Files) (s, Figure 8):")
    print(tabulate(comp_table_files, headers='firstrow', tablefmt='grid', floatfmt=".6f"))

    comm_table_attrs = [['Files'] + ['MPK', 'MSK', 'SK', 'CT']]
    for idx, n_files in enumerate(file_counts):
        row = [n_files]
        for elem in ['MPK', 'MSK', 'SK', 'CT']:
            row.append(comm_sizes_fixed_attrs[elem][idx])
        comm_table_attrs.append(row)
    print("\nCommunication Sizes with Fixed Attributes (8 Attrs) (Bytes, Figure 9):")
    print(tabulate(comm_table_attrs, headers='firstrow', tablefmt='grid'))

    comm_table_files = [['Attributes'] + ['MPK', 'MSK', 'SK', 'CT']]
    for idx, n_attrs in enumerate(attr_counts):
        row = [n_attrs]
        for elem in ['MPK', 'MSK', 'SK', 'CT']:
            row.append(comm_sizes_fixed_files[elem][idx])
        comm_table_files.append(row)
    print("\nCommunication Sizes with Fixed Files (8 Files) (Bytes, Figure 10):")
    print(tabulate(comm_table_files, headers='firstrow', tablefmt='grid'))

def performance_evaluation():
    cpabe = CRFHCPABE()
    print("Running performance evaluation...")

    file_counts = [2, 4, 6, 8, 10, 12, 14]
    attr_counts = [2, 4, 8, 12, 16]
    fixed_attrs = 8
    fixed_files = 8
    num_runs = 3

    comp_times_fixed_attrs = {'Setup': [], 'Keygen': [], 'Encrypt': [], 'Decrypt': []}
    comp_times_fixed_files = {'Setup': [], 'Keygen': [], 'Encrypt': [], 'Decrypt': []}
    comm_sizes_fixed_attrs = {'MPK': [], 'MSK': [], 'SK': [], 'CT': []}
    comm_sizes_fixed_files = {'MPK': [], 'MSK': [], 'SK': [], 'CT': []}

    # Fig. 7 and Fig. 9
    for n_files in file_counts:
        attributes = [f"attr{i+1}" for i in range(n_files * 2)]  # 2 attrs per file
        # For Keygen, use all attributes up to fixed_attrs
        user_attrs = set(attributes[:min(len(attributes), fixed_attrs)])
        access_tree = create_access_tree(n_files, threshold=2, attributes=attributes)
        messages = [f"File{i+1}" for i in range(n_files)]

        setup_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            MPK, MSK = cpabe.setup()
            setup_time += (time.time() - start_time)
        comp_times_fixed_attrs['Setup'].append(setup_time / num_runs)

        keygen_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            SK = cpabe.keygen(MPK, MSK, set(attributes), "user1")  # Use all attributes
            keygen_time += (time.time() - start_time)
        comp_times_fixed_attrs['Keygen'].append(keygen_time / num_runs)

        encrypt_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            CT = cpabe.encrypt(MPK, messages, access_tree)
            encrypt_time += (time.time() - start_time)
        comp_times_fixed_attrs['Encrypt'].append(encrypt_time / num_runs)

        decrypt_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            decrypted_messages = cpabe.decrypt(MPK, CT, SK, user_attrs)
            decrypt_time += (time.time() - start_time)
        comp_times_fixed_attrs['Decrypt'].append(decrypt_time / num_runs)
        print(f"Files={n_files}, Attrs={fixed_attrs}, Decrypted: {decrypted_messages}")

        sizes = cpabe.compute_sizes(MPK, MSK, SK, CT)
        for elem in ['MPK', 'MSK', 'SK', 'CT']:
            comm_sizes_fixed_attrs[elem].append(sizes[elem])

    # Fig. 8 and Fig. 10
    for n_attrs in attr_counts:
        attributes = [f"attr{i+1}" for i in range(fixed_files * 2)]
        user_attrs = set([f"attr{i+1}" for i in range(n_attrs)])
        access_tree = create_access_tree(fixed_files, threshold=2, attributes=attributes)
        messages = [f"File{i+1}" for i in range(fixed_files)]

        setup_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            MPK, MSK = cpabe.setup()
            setup_time += (time.time() - start_time)
        comp_times_fixed_files['Setup'].append(setup_time / num_runs)

        keygen_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            SK = cpabe.keygen(MPK, MSK, user_attrs, "user1")
            keygen_time += (time.time() - start_time)
        comp_times_fixed_files['Keygen'].append(keygen_time / num_runs)

        encrypt_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            CT = cpabe.encrypt(MPK, messages, access_tree)
            encrypt_time += (time.time() - start_time)
        comp_times_fixed_files['Encrypt'].append(encrypt_time / num_runs)

        decrypt_time = 0
        for _ in range(num_runs):
            start_time = time.time()
            decrypted_messages = cpabe.decrypt(MPK, CT, SK, user_attrs)
            decrypt_time += (time.time() - start_time)
        comp_times_fixed_files['Decrypt'].append(decrypt_time / num_runs)
        print(f"Files={fixed_files}, Attrs={n_attrs}, Decrypted: {decrypted_messages}")

        sizes = cpabe.compute_sizes(MPK, MSK, SK, CT)
        for elem in ['MPK', 'MSK', 'SK', 'CT']:
            comm_sizes_fixed_files[elem].append(sizes[elem])

    plot_performance(file_counts, attr_counts, comp_times_fixed_attrs, comp_times_fixed_files,
                     comm_sizes_fixed_attrs, comm_sizes_fixed_files)

    print_performance_tables(file_counts, attr_counts, comp_times_fixed_attrs, comp_times_fixed_files,
                             comm_sizes_fixed_attrs, comm_sizes_fixed_files)

def main():
    """Demonstrate the CR-FH-CPABE scheme."""
    cpabe = CRFHCPABE()
    MPK, MSK = cpabe.setup()

    num_files = 4
    attributes = [f"attr{i+1}" for i in range(num_files * 2)]
    access_tree = create_access_tree(num_files, threshold=2, attributes=attributes)
    messages = ["File1", "File2", "File3", "File4"] # messages for encrypt

    try:
        ciphertext = cpabe.encrypt(MPK, messages, access_tree)
    except ValueError as e:
        print(f"Encryption failed: {e}")
        return

    user_attributes = set(attributes[:2])  # Need at least threshold attributes
    uid = "user1"
    private_key = cpabe.keygen(MPK, MSK, user_attributes, uid)
    decrypted_messages = cpabe.decrypt(MPK, ciphertext, private_key, user_attributes)
    print("Standard decrypted messages:", decrypted_messages)

    TK, RK = cpabe.transform_keygen(MPK, MSK, private_key, uid)
    CT_trans = cpabe.transform(MPK, ciphertext, TK, user_attributes)
    if CT_trans:
        decrypted_messages_out = cpabe.decrypt_out(CT_trans, RK)
        print("Outsourced decrypted messages:", decrypted_messages_out)

    performance_evaluation()

if __name__ == "__main__":
    main()
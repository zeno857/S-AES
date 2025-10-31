import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import numpy as np
from typing import List, Tuple


class SAES:
    """
    S-AES (Simplified AES) 实现类
    基于《密码编码学与网络安全—原理与实践(第8版)》附录D
    """

    # S盒和逆S盒
    S_BOX = [
        [0x9, 0x4, 0xA, 0xB],
        [0xD, 0x1, 0x8, 0x5],
        [0x6, 0x2, 0x0, 0x3],
        [0xC, 0xE, 0xF, 0x7]
    ]

    INV_S_BOX = [
        [0xA, 0x5, 0x9, 0xB],
        [0x1, 0x7, 0x8, 0xF],
        [0x6, 0x0, 0x2, 0x3],
        [0xC, 0x4, 0xD, 0xE]
    ]

    # 列混淆矩阵
    MIX_MATRIX = [[1, 4], [4, 1]]
    INV_MIX_MATRIX = [[9, 2], [2, 9]]

    # RCON常量
    RCON = [0x80, 0x30]  # RCON(1)=10000000, RCON(2)=00110000

    def __init__(self):
        # GF(2^4)乘法表（预计算）
        self.gf_mul_table = self._precompute_gf_multiplication()

    def _precompute_gf_multiplication(self):
        """预计算GF(2^4)上的乘法结果"""
        mul_table = {}
        for a in range(16):
            for b in range(16):
                mul_table[(a, b)] = self._gf_multiply(a, b)
        return mul_table

    def _gf_multiply(self, a: int, b: int) -> int:
        """
        GF(2^4)上的乘法，模多项式 x^4 + x + 1
        """
        if a == 0 or b == 0:
            return 0

        result = 0
        for i in range(4):
            if (b >> i) & 1:
                temp = a
                for j in range(i):
                    temp <<= 1
                    if temp & 0x10:
                        temp ^= 0x13  # x^4 + x + 1 = 10011
                result ^= temp

        # 模约简
        while result >= 0x10:
            if result & 0x10:
                result ^= 0x13
            result &= 0xF

        return result

    def _nibble_substitution(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """半字节代替"""
        s_box = self.INV_S_BOX if inverse else self.S_BOX
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                nibble = state[i][j]
                row = (nibble >> 2) & 0x3
                col = nibble & 0x3
                new_state[i][j] = s_box[row][col]

        return new_state

    def _shift_rows(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """行移位"""
        new_state = [state[0][:], state[1][:]]  # 复制状态
        if not inverse:
            # 加密：第二行循环左移1个半字节
            new_state[1] = [state[1][1], state[1][0]]
        else:
            # 解密：第二行循环右移1个半字节（与加密相同）
            new_state[1] = [state[1][1], state[1][0]]

        return new_state

    def _mix_columns(self, state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """列混淆"""
        matrix = self.INV_MIX_MATRIX if inverse else self.MIX_MATRIX
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                result = 0
                for k in range(2):
                    mul_result = self.gf_mul_table[(matrix[i][k], state[k][j])]
                    result ^= mul_result
                new_state[i][j] = result & 0xF

        return new_state

    def _add_round_key(self, state: List[List[int]], round_key: List[List[int]]) -> List[List[int]]:
        """轮密钥加"""
        new_state = [[0, 0], [0, 0]]

        for i in range(2):
            for j in range(2):
                new_state[i][j] = state[i][j] ^ round_key[i][j]

        return new_state

    def _key_expansion(self, key: int) -> List[List[List[int]]]:
        """密钥扩展"""
        # 将16位密钥分成两个字节
        w0 = [(key >> 12) & 0xF, (key >> 8) & 0xF]
        w1 = [(key >> 4) & 0xF, key & 0xF]

        # 计算w2
        temp = self._rot_nib(w1)
        temp = self._sub_nib(temp)
        temp[0] ^= (self.RCON[0] >> 4) & 0xF
        temp[1] ^= self.RCON[0] & 0xF

        w2 = [w0[0] ^ temp[0], w0[1] ^ temp[1]]

        # 计算w3
        w3 = [w2[0] ^ w1[0], w2[1] ^ w1[1]]

        # 计算w4
        temp = self._rot_nib(w3)
        temp = self._sub_nib(temp)
        temp[0] ^= (self.RCON[1] >> 4) & 0xF
        temp[1] ^= self.RCON[1] & 0xF

        w4 = [w2[0] ^ temp[0], w2[1] ^ temp[1]]

        # 计算w5
        w5 = [w4[0] ^ w3[0], w4[1] ^ w3[1]]

        # 组织轮密钥
        round_keys = [
            [[w0[0], w0[1]], [w1[0], w1[1]]],  # K0
            [[w2[0], w2[1]], [w3[0], w3[1]]],  # K1
            [[w4[0], w4[1]], [w5[0], w5[1]]]  # K2
        ]

        return round_keys

    def _rot_nib(self, nibbles: List[int]) -> List[int]:
        """半字节循环移位"""
        return [nibbles[1], nibbles[0]]

    def _sub_nib(self, nibbles: List[int]) -> List[int]:
        """半字节代替（用于密钥扩展）"""
        result = []
        for nibble in nibbles:
            row = (nibble >> 2) & 0x3
            col = nibble & 0x3
            result.append(self.S_BOX[row][col])
        return result

    def _int_to_state(self, value: int) -> List[List[int]]:
        """将16位整数转换为状态矩阵"""
        return [
            [(value >> 12) & 0xF, (value >> 8) & 0xF],
            [(value >> 4) & 0xF, value & 0xF]
        ]

    def _state_to_int(self, state: List[List[int]]) -> int:
        """将状态矩阵转换为16位整数"""
        result = 0
        result |= (state[0][0] & 0xF) << 12
        result |= (state[0][1] & 0xF) << 8
        result |= (state[1][0] & 0xF) << 4
        result |= (state[1][1] & 0xF)
        return result

    def encrypt(self, plaintext: int, key: int) -> int:
        """加密16位明文"""
        state = self._int_to_state(plaintext)
        round_keys = self._key_expansion(key)

        # 第0轮：轮密钥加
        state = self._add_round_key(state, round_keys[0])

        # 第1轮：完整轮
        state = self._nibble_substitution(state)
        state = self._shift_rows(state)
        state = self._mix_columns(state)
        state = self._add_round_key(state, round_keys[1])

        # 第2轮：简化轮
        state = self._nibble_substitution(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[2])

        return self._state_to_int(state)

    def decrypt(self, ciphertext: int, key: int) -> int:
        """解密16位密文"""
        state = self._int_to_state(ciphertext)
        round_keys = self._key_expansion(key)

        # 第2轮逆操作
        state = self._add_round_key(state, round_keys[2])
        state = self._shift_rows(state, inverse=True)
        state = self._nibble_substitution(state, inverse=True)

        # 第1轮逆操作
        state = self._add_round_key(state, round_keys[1])
        state = self._mix_columns(state, inverse=True)
        state = self._shift_rows(state, inverse=True)
        state = self._nibble_substitution(state, inverse=True)

        # 第0轮逆操作
        state = self._add_round_key(state, round_keys[0])

        return self._state_to_int(state)


class DoubleSAES:
    """双重S-AES实现"""

    def __init__(self):
        self.saes = SAES()

    def encrypt(self, plaintext: int, key: int) -> int:
        """双重加密"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        intermediate = self.saes.encrypt(plaintext, k1)
        return self.saes.encrypt(intermediate, k2)

    def decrypt(self, ciphertext: int, key: int) -> int:
        """双重解密"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        intermediate = self.saes.decrypt(ciphertext, k2)
        return self.saes.decrypt(intermediate, k1)


class TripleSAES:
    """三重S-AES实现"""

    def __init__(self):
        self.saes = SAES()

    def encrypt_32bit(self, plaintext: int, key: int) -> int:
        """32位密钥的三重加密 (K1, K2, K1)"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        temp = self.saes.encrypt(plaintext, k1)
        temp = self.saes.encrypt(temp, k2)
        return self.saes.encrypt(temp, k1)

    def decrypt_32bit(self, ciphertext: int, key: int) -> int:
        """32位密钥的三重解密"""
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        temp = self.saes.decrypt(ciphertext, k1)
        temp = self.saes.decrypt(temp, k2)
        return self.saes.decrypt(temp, k1)

    def encrypt_48bit(self, plaintext: int, key: int) -> int:
        """48位密钥的三重加密 (K1, K2, K3)"""
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        temp = self.saes.encrypt(plaintext, k1)
        temp = self.saes.encrypt(temp, k2)
        return self.saes.encrypt(temp, k3)

    def decrypt_48bit(self, ciphertext: int, key: int) -> int:
        """48位密钥的三重解密"""
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        temp = self.saes.decrypt(ciphertext, k3)
        temp = self.saes.decrypt(temp, k2)
        return self.saes.decrypt(temp, k1)


class CBCMode:
    """CBC工作模式实现"""

    def __init__(self, saes: SAES):
        self.saes = saes

    def encrypt(self, plaintext_blocks: List[int], key: int, iv: int) -> List[int]:
        """CBC模式加密"""
        ciphertext_blocks = []
        previous_block = iv

        for block in plaintext_blocks:
            # 与前一密文块异或
            xored_block = block ^ previous_block
            # 加密
            encrypted_block = self.saes.encrypt(xored_block, key)
            ciphertext_blocks.append(encrypted_block)
            previous_block = encrypted_block

        return ciphertext_blocks

    def decrypt(self, ciphertext_blocks: List[int], key: int, iv: int) -> List[int]:
        """CBC模式解密"""
        plaintext_blocks = []
        previous_block = iv

        for block in ciphertext_blocks:
            # 解密
            decrypted_block = self.saes.decrypt(block, key)
            # 与前一密文块异或
            xored_block = decrypted_block ^ previous_block
            plaintext_blocks.append(xored_block)
            previous_block = block

        return plaintext_blocks


class SAESGUI:
    """S-AES图形用户界面"""

    def __init__(self, root):
        self.root = root
        self.root.title("S-AES加密解密系统")
        self.root.geometry("800x600")

        # 初始化算法实例
        self.saes = SAES()
        self.double_saes = DoubleSAES()
        self.triple_saes = TripleSAES()
        self.cbc_mode = CBCMode(self.saes)

        self.setup_ui()

    def setup_ui(self):
        """设置用户界面"""
        # 创建选项卡
        notebook = ttk.Notebook(self.root)

        # 基本测试选项卡
        basic_frame = ttk.Frame(notebook)
        self.setup_basic_tab(basic_frame)

        # ASCII加密选项卡
        ascii_frame = ttk.Frame(notebook)
        self.setup_ascii_tab(ascii_frame)

        # 多重加密选项卡
        multi_frame = ttk.Frame(notebook)
        self.setup_multi_tab(multi_frame)

        # CBC模式选项卡
        cbc_frame = ttk.Frame(notebook)
        self.setup_cbc_tab(cbc_frame)

        # 添加所有选项卡
        notebook.add(basic_frame, text="基本测试")
        notebook.add(ascii_frame, text="ASCII加密")
        notebook.add(multi_frame, text="多重加密")
        notebook.add(cbc_frame, text="CBC模式")
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

    def setup_basic_tab(self, parent):
        """设置基本测试选项卡"""
        # 输入框架
        input_frame = ttk.LabelFrame(parent, text="输入", padding=10)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text="明文 (16位):").grid(row=0, column=0, sticky='w')
        self.plaintext_entry = ttk.Entry(input_frame, width=20)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=1, column=0, sticky='w')
        self.key_entry = ttk.Entry(input_frame, width=20)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(button_frame, text="加密", command=self.basic_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密", command=self.basic_decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_basic).pack(side='left', padx=5)

        # 输出框架
        output_frame = ttk.LabelFrame(parent, text="输出", padding=10)
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.basic_output = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.basic_output.pack(fill='both', expand=True)

    def setup_ascii_tab(self, parent):
        """设置ASCII加密选项卡"""
        # 输入框架
        input_frame = ttk.LabelFrame(parent, text="ASCII输入", padding=10)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text="ASCII文本:").grid(row=0, column=0, sticky='w')
        self.ascii_text_entry = scrolledtext.ScrolledText(input_frame, height=3, width=50)
        self.ascii_text_entry.grid(row=0, column=1, padx=5, pady=5, rowspan=2)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=2, column=0, sticky='w')
        self.ascii_key_entry = ttk.Entry(input_frame, width=20)
        self.ascii_key_entry.grid(row=2, column=1, padx=5, pady=5, sticky='w')

        # 按钮框架
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(button_frame, text="加密", command=self.ascii_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密", command=self.ascii_decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_ascii).pack(side='left', padx=5)

        # 输出框架
        output_frame = ttk.LabelFrame(parent, text="输出", padding=10)
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.ascii_output = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.ascii_output.pack(fill='both', expand=True)

    def setup_multi_tab(self, parent):
        """设置多重加密选项卡"""
        # 加密类型选择
        type_frame = ttk.LabelFrame(parent, text="加密类型", padding=10)
        type_frame.pack(fill='x', padx=5, pady=5)

        self.encryption_type = tk.StringVar(value="double")
        ttk.Radiobutton(type_frame, text="双重加密 (32位密钥)",
                        variable=self.encryption_type, value="double").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="三重加密-32位密钥",
                        variable=self.encryption_type, value="triple_32").pack(anchor='w')
        ttk.Radiobutton(type_frame, text="三重加密-48位密钥",
                        variable=self.encryption_type, value="triple_48").pack(anchor='w')

        # 输入框架
        input_frame = ttk.LabelFrame(parent, text="输入", padding=10)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text="明文:").grid(row=0, column=0, sticky='w')
        self.multi_plaintext_entry = ttk.Entry(input_frame, width=20)
        self.multi_plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥:").grid(row=1, column=0, sticky='w')
        self.multi_key_entry = ttk.Entry(input_frame, width=20)
        self.multi_key_entry.grid(row=1, column=1, padx=5, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(button_frame, text="加密", command=self.multi_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="解密", command=self.multi_decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="中间相遇攻击", command=self.meet_in_middle).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_multi).pack(side='left', padx=5)

        # 输出框架
        output_frame = ttk.LabelFrame(parent, text="输出", padding=10)
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.multi_output = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.multi_output.pack(fill='both', expand=True)

    def setup_cbc_tab(self, parent):
        """设置CBC模式选项卡"""
        # 输入框架
        input_frame = ttk.LabelFrame(parent, text="CBC模式输入", padding=10)
        input_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(input_frame, text="明文 (16位分组，用空格分隔):").grid(row=0, column=0, sticky='w')
        self.cbc_plaintext_entry = ttk.Entry(input_frame, width=30)
        self.cbc_plaintext_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="密钥 (16位):").grid(row=1, column=0, sticky='w')
        self.cbc_key_entry = ttk.Entry(input_frame, width=20)
        self.cbc_key_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="初始向量 (16位):").grid(row=2, column=0, sticky='w')
        self.iv_entry = ttk.Entry(input_frame, width=20)
        self.iv_entry.grid(row=2, column=1, padx=5, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill='x', padx=5, pady=5)

        ttk.Button(button_frame, text="CBC加密", command=self.cbc_encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="CBC解密", command=self.cbc_decrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="篡改测试", command=self.tamper_test).pack(side='left', padx=5)
        ttk.Button(button_frame, text="清空", command=self.clear_cbc).pack(side='left', padx=5)

        # 输出框架
        output_frame = ttk.LabelFrame(parent, text="CBC输出", padding=10)
        output_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.cbc_output = scrolledtext.ScrolledText(output_frame, height=10, width=70)
        self.cbc_output.pack(fill='both', expand=True)

    # 基本测试功能
    def basic_encrypt(self):
        try:
            plaintext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)

            if plaintext > 0xFFFF or key > 0xFFFF:
                messagebox.showerror("错误", "明文和密钥必须是16位")
                return

            ciphertext = self.saes.encrypt(plaintext, key)

            output = f"明文: {plaintext:04X}\n"
            output += f"密钥: {key:04X}\n"
            output += f"密文: {ciphertext:04X}\n"

            self.basic_output.delete(1.0, tk.END)
            self.basic_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def basic_decrypt(self):
        try:
            ciphertext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)

            if ciphertext > 0xFFFF or key > 0xFFFF:
                messagebox.showerror("错误", "密文和密钥必须是16位")
                return

            plaintext = self.saes.decrypt(ciphertext, key)

            output = f"密文: {ciphertext:04X}\n"
            output += f"密钥: {key:04X}\n"
            output += f"明文: {plaintext:04X}\n"

            self.basic_output.delete(1.0, tk.END)
            self.basic_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def clear_basic(self):
        self.plaintext_entry.delete(0, tk.END)
        self.key_entry.delete(0, tk.END)
        self.basic_output.delete(1.0, tk.END)

    # ASCII加密功能
    def ascii_encrypt(self):
        try:
            text = self.ascii_text_entry.get(1.0, tk.END).strip()
            key = int(self.ascii_key_entry.get(), 16)

            if key > 0xFFFF:
                messagebox.showerror("错误", "密钥必须是16位")
                return

            # 将文本转换为16位分组
            blocks = []
            for i in range(0, len(text), 2):
                block = 0
                if i < len(text):
                    block |= ord(text[i]) << 8
                if i + 1 < len(text):
                    block |= ord(text[i + 1])
                blocks.append(block)

            # 加密每个分组
            encrypted_blocks = [self.saes.encrypt(block, key) for block in blocks]

            # 转换为ASCII字符串（可能是乱码）
            encrypted_text = ''.join(chr((block >> 8) & 0xFF) + chr(block & 0xFF)
                                     for block in encrypted_blocks)

            output = f"原始文本: {text}\n"
            output += f"密钥: {key:04X}\n"
            output += f"加密后(十六进制): {' '.join(f'{block:04X}' for block in encrypted_blocks)}\n"
            output += f"加密后(ASCII): {encrypted_text}\n"

            self.ascii_output.delete(1.0, tk.END)
            self.ascii_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的密钥")

    def ascii_decrypt(self):
        try:
            text = self.ascii_text_entry.get(1.0, tk.END).strip()
            key = int(self.ascii_key_entry.get(), 16)

            if key > 0xFFFF:
                messagebox.showerror("错误", "密钥必须是16位")
                return

            # 将文本转换为16位分组
            blocks = []
            for i in range(0, len(text), 2):
                block = 0
                if i < len(text):
                    block |= ord(text[i]) << 8
                if i + 1 < len(text):
                    block |= ord(text[i + 1])
                blocks.append(block)

            # 解密每个分组
            decrypted_blocks = [self.saes.decrypt(block, key) for block in blocks]

            # 转换为ASCII字符串
            decrypted_text = ''.join(chr((block >> 8) & 0xFF) + chr(block & 0xFF)
                                     for block in decrypted_blocks)

            output = f"加密文本: {text}\n"
            output += f"密钥: {key:04X}\n"
            output += f"解密后(十六进制): {' '.join(f'{block:04X}' for block in decrypted_blocks)}\n"
            output += f"解密后(ASCII): {decrypted_text}\n"

            self.ascii_output.delete(1.0, tk.END)
            self.ascii_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的密钥")

    def clear_ascii(self):
        self.ascii_text_entry.delete(1.0, tk.END)
        self.ascii_key_entry.delete(0, tk.END)
        self.ascii_output.delete(1.0, tk.END)

    # 多重加密功能
    def multi_encrypt(self):
        try:
            plaintext = int(self.multi_plaintext_entry.get(), 16)
            key = int(self.multi_key_entry.get(), 16)
            enc_type = self.encryption_type.get()

            if enc_type == "double":
                if key > 0xFFFFFFFF:
                    messagebox.showerror("错误", "双重加密密钥必须是32位")
                    return
                ciphertext = self.double_saes.encrypt(plaintext, key)
                key_info = f"K1: {(key >> 16) & 0xFFFF:04X}, K2: {key & 0xFFFF:04X}"
            elif enc_type == "triple_32":
                if key > 0xFFFFFFFF:
                    messagebox.showerror("错误", "三重加密密钥必须是32位")
                    return
                ciphertext = self.triple_saes.encrypt_32bit(plaintext, key)
                key_info = f"K1: {(key >> 16) & 0xFFFF:04X}, K2: {key & 0xFFFF:04X}"
            else:  # triple_48
                if key > 0xFFFFFFFFFFFF:
                    messagebox.showerror("错误", "三重加密密钥必须是48位")
                    return
                ciphertext = self.triple_saes.encrypt_48bit(plaintext, key)
                key_info = f"K1: {(key >> 32) & 0xFFFF:04X}, K2: {(key >> 16) & 0xFFFF:04X}, K3: {key & 0xFFFF:04X}"

            output = f"加密类型: {self.get_enc_type_name(enc_type)}\n"
            output += f"明文: {plaintext:04X}\n"
            output += f"密钥: {key_info}\n"
            output += f"密文: {ciphertext:04X}\n"

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def multi_decrypt(self):
        try:
            ciphertext = int(self.multi_plaintext_entry.get(), 16)
            key = int(self.multi_key_entry.get(), 16)
            enc_type = self.encryption_type.get()

            if enc_type == "double":
                if key > 0xFFFFFFFF:
                    messagebox.showerror("错误", "双重加密密钥必须是32位")
                    return
                plaintext = self.double_saes.decrypt(ciphertext, key)
                key_info = f"K1: {(key >> 16) & 0xFFFF:04X}, K2: {key & 0xFFFF:04X}"
            elif enc_type == "triple_32":
                if key > 0xFFFFFFFF:
                    messagebox.showerror("错误", "三重加密密钥必须是32位")
                    return
                plaintext = self.triple_saes.decrypt_32bit(ciphertext, key)
                key_info = f"K1: {(key >> 16) & 0xFFFF:04X}, K2: {key & 0xFFFF:04X}"
            else:  # triple_48
                if key > 0xFFFFFFFFFFFF:
                    messagebox.showerror("错误", "三重加密密钥必须是48位")
                    return
                plaintext = self.triple_saes.decrypt_48bit(ciphertext, key)
                key_info = f"K1: {(key >> 32) & 0xFFFF:04X}, K2: {(key >> 16) & 0xFFFF:04X}, K3: {key & 0xFFFF:04X}"

            output = f"加密类型: {self.get_enc_type_name(enc_type)}\n"
            output += f"密文: {ciphertext:04X}\n"
            output += f"密钥: {key_info}\n"
            output += f"明文: {plaintext:04X}\n"

            self.multi_output.delete(1.0, tk.END)
            self.multi_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def meet_in_middle(self):
        """中间相遇攻击 - 简化版本"""
        try:
            # 创建攻击窗口
            attack_window = tk.Toplevel(self.root)
            attack_window.title("中间相遇攻击")
            attack_window.geometry("600x400")

            # 输入框架
            input_frame = ttk.LabelFrame(attack_window, text="已知明密文对", padding=10)
            input_frame.pack(fill='x', padx=10, pady=5)

            ttk.Label(input_frame, text="明文 (16位):").grid(row=0, column=0, sticky='w', padx=5, pady=2)
            plaintext_entry = ttk.Entry(input_frame, width=10)
            plaintext_entry.grid(row=0, column=1, padx=5, pady=2)
            plaintext_entry.insert(0, "1234")

            ttk.Label(input_frame, text="密文 (16位):").grid(row=0, column=2, sticky='w', padx=5, pady=2)
            ciphertext_entry = ttk.Entry(input_frame, width=10)
            ciphertext_entry.grid(row=0, column=3, padx=5, pady=2)
            ciphertext_entry.insert(0, "C9A8")

            # 攻击参数框架
            param_frame = ttk.LabelFrame(attack_window, text="攻击参数", padding=10)
            param_frame.pack(fill='x', padx=10, pady=5)

            ttk.Label(param_frame, text="搜索范围 (起始):").grid(row=0, column=0, sticky='w', padx=5, pady=2)
            start_key_entry = ttk.Entry(param_frame, width=8)
            start_key_entry.grid(row=0, column=1, padx=5, pady=2)
            start_key_entry.insert(0, "1000")

            ttk.Label(param_frame, text="搜索范围 (结束):").grid(row=0, column=2, sticky='w', padx=5, pady=2)
            end_key_entry = ttk.Entry(param_frame, width=8)
            end_key_entry.grid(row=0, column=3, padx=5, pady=2)
            end_key_entry.insert(0, "1010")  # 小范围测试

            # 输出框架
            output_frame = ttk.LabelFrame(attack_window, text="攻击结果", padding=10)
            output_frame.pack(fill='both', expand=True, padx=10, pady=5)

            output_text = scrolledtext.ScrolledText(output_frame, height=15, width=70)
            output_text.pack(fill='both', expand=True)

            def execute_attack():
                """执行中间相遇攻击"""
                try:
                    # 获取输入参数
                    plaintext = int(plaintext_entry.get(), 16)
                    ciphertext = int(ciphertext_entry.get(), 16)
                    start_key = int(start_key_entry.get(), 16)
                    end_key = int(end_key_entry.get(), 16)

                    if start_key > end_key:
                        messagebox.showerror("错误", "起始密钥必须小于等于结束密钥")
                        return

                    # 清空输出
                    output_text.delete(1.0, tk.END)
                    output_text.insert(tk.END, "开始中间相遇攻击...\n")
                    output_text.update()

                    # 执行攻击
                    self._simple_meet_in_middle(plaintext, ciphertext, start_key, end_key, output_text)

                except ValueError as e:
                    messagebox.showerror("错误", f"输入参数错误: {e}")
                except Exception as e:
                    messagebox.showerror("错误", f"攻击执行失败: {e}")

            def quick_demo():
                """快速演示"""
                # 使用已知的明密文对和密钥
                plaintext_entry.delete(0, tk.END)
                plaintext_entry.insert(0, "1234")
                ciphertext_entry.delete(0, tk.END)
                ciphertext_entry.insert(0, "C9A8")
                start_key_entry.delete(0, tk.END)
                start_key_entry.insert(0, "1000")
                end_key_entry.delete(0, tk.END)
                end_key_entry.insert(0, "1010")

            # 按钮框架
            button_frame = ttk.Frame(attack_window)
            button_frame.pack(fill='x', padx=10, pady=5)

            ttk.Button(button_frame, text="执行攻击",
                       command=execute_attack).pack(side='left', padx=5)
            ttk.Button(button_frame, text="快速演示",
                       command=quick_demo).pack(side='left', padx=5)
            ttk.Button(button_frame, text="清空",
                       command=lambda: output_text.delete(1.0, tk.END)).pack(side='left', padx=5)
            ttk.Button(button_frame, text="关闭",
                       command=attack_window.destroy).pack(side='right', padx=5)

        except Exception as e:
            messagebox.showerror("错误", f"创建攻击窗口失败: {e}")

    def _simple_meet_in_middle(self, plaintext, ciphertext, start_key, end_key, output_text):
        """简化版中间相遇攻击"""
        output_text.insert(tk.END, f"搜索范围: K1,K2 ∈ [{start_key:04X}, {end_key:04X}]\n")
        output_text.insert(tk.END, "正在构建中间值表...\n")
        output_text.update()

        # 阶段1: 构建中间值表 (K1 -> 中间值)
        intermediate_table = {}
        for k1 in range(start_key, end_key + 1):
            intermediate = self.saes.encrypt(plaintext, k1)
            if intermediate not in intermediate_table:
                intermediate_table[intermediate] = []
            intermediate_table[intermediate].append(k1)

        output_text.insert(tk.END, f"中间值表构建完成，共有 {len(intermediate_table)} 个不同的中间值\n")
        output_text.insert(tk.END, "正在匹配密钥...\n")
        output_text.update()

        # 阶段2: 查找匹配的K2
        candidate_keys = []
        for k2 in range(start_key, end_key + 1):
            intermediate = self.saes.decrypt(ciphertext, k2)

            if intermediate in intermediate_table:
                for k1 in intermediate_table[intermediate]:
                    candidate_keys.append((k1, k2))

        # 显示结果
        self._display_simple_attack_results(candidate_keys, output_text)

    def _display_simple_attack_results(self, candidate_keys, output_text):
        """显示简化版攻击结果"""
        output_text.insert(tk.END, "\n" + "=" * 50 + "\n")
        output_text.insert(tk.END, "攻击完成！\n\n")

        if candidate_keys:
            output_text.insert(tk.END, f"找到 {len(candidate_keys)} 个候选密钥对:\n")
            output_text.insert(tk.END, "-" * 40 + "\n")

            for i, (k1, k2) in enumerate(candidate_keys, 1):
                full_key = (k1 << 16) | k2
                output_text.insert(tk.END, f"{i:2d}. K1 = {k1:04X}, K2 = {k2:04X}\n")
                output_text.insert(tk.END, f"    完整密钥 = {full_key:08X}\n")

                # 测试加密验证
                test_plain = 0x1234  # 测试明文
                test_cipher = self.double_saes.encrypt(test_plain, full_key)
                output_text.insert(tk.END, f"    测试: E(0x1234) = {test_cipher:04X}\n")
                output_text.insert(tk.END, "-" * 40 + "\n")

            if len(candidate_keys) == 1:
                output_text.insert(tk.END, "\n🎉 成功找到唯一密钥！\n")
            else:
                output_text.insert(tk.END, f"\n⚠️ 找到多个候选密钥，需要使用更多明密文对进一步验证\n")
        else:
            output_text.insert(tk.END, "❌ 未找到匹配的密钥对\n")
            output_text.insert(tk.END, "可能原因:\n")
            output_text.insert(tk.END, "1. 明密文对不正确\n")
            output_text.insert(tk.END, "2. 密钥不在搜索范围内\n")
            output_text.insert(tk.END, "3. 需要更多明密文对进行验证\n")

        output_text.insert(tk.END, "\n攻击统计:\n")
        output_text.insert(tk.END, f"- 时间复杂度: O(2^(n+1)) 而不是 O(2^(2n))\n")
        output_text.insert(tk.END, f"- 空间复杂度: O(2^n) 用于存储中间值表\n")
        output_text.insert(tk.END, f"- 对于16位密钥，攻击需要约 2×2^16 = 131,072 次加密操作\n")
        output_text.insert(tk.END, f"- 相比暴力破解的 2^32 = 4,294,967,296 次，效率大大提高\n")

    def clear_multi(self):
        self.multi_plaintext_entry.delete(0, tk.END)
        self.multi_key_entry.delete(0, tk.END)
        self.multi_output.delete(1.0, tk.END)

    # CBC模式功能
    def cbc_encrypt(self):
        try:
            plaintext_str = self.cbc_plaintext_entry.get()
            key = int(self.cbc_key_entry.get(), 16)
            iv = int(self.iv_entry.get(), 16)

            if key > 0xFFFF or iv > 0xFFFF:
                messagebox.showerror("错误", "密钥和初始向量必须是16位")
                return

            # 解析明文分组
            plaintext_blocks = [int(x, 16) for x in plaintext_str.split()]

            # CBC加密
            ciphertext_blocks = self.cbc_mode.encrypt(plaintext_blocks, key, iv)

            output = f"明文分组: {' '.join(f'{block:04X}' for block in plaintext_blocks)}\n"
            output += f"密钥: {key:04X}\n"
            output += f"初始向量: {iv:04X}\n"
            output += f"密文分组: {' '.join(f'{block:04X}' for block in ciphertext_blocks)}\n"

            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def cbc_decrypt(self):
        try:
            ciphertext_str = self.cbc_plaintext_entry.get()  # 重用输入框
            key = int(self.cbc_key_entry.get(), 16)
            iv = int(self.iv_entry.get(), 16)

            if key > 0xFFFF or iv > 0xFFFF:
                messagebox.showerror("错误", "密钥和初始向量必须是16位")
                return

            # 解析密文分组
            ciphertext_blocks = [int(x, 16) for x in ciphertext_str.split()]

            # CBC解密
            plaintext_blocks = self.cbc_mode.decrypt(ciphertext_blocks, key, iv)

            output = f"密文分组: {' '.join(f'{block:04X}' for block in ciphertext_blocks)}\n"
            output += f"密钥: {key:04X}\n"
            output += f"初始向量: {iv:04X}\n"
            output += f"明文分组: {' '.join(f'{block:04X}' for block in plaintext_blocks)}\n"

            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def tamper_test(self):
        """篡改测试"""
        try:
            plaintext_str = self.cbc_plaintext_entry.get()
            key = int(self.cbc_key_entry.get(), 16)
            iv = int(self.iv_entry.get(), 16)

            if key > 0xFFFF or iv > 0xFFFF:
                messagebox.showerror("错误", "密钥和初始向量必须是16位")
                return

            # 解析明文分组
            plaintext_blocks = [int(x, 16) for x in plaintext_str.split()]

            # 正常加密
            ciphertext_blocks = self.cbc_mode.encrypt(plaintext_blocks, key, iv)

            # 篡改一个密文分组（例如第二个分组）
            if len(ciphertext_blocks) > 1:
                tampered_blocks = ciphertext_blocks.copy()
                tampered_blocks[1] ^= 0x0F0F  # 篡改一些位

                # 解密篡改后的密文
                decrypted_blocks = self.cbc_mode.decrypt(tampered_blocks, key, iv)
            else:
                tampered_blocks = ciphertext_blocks.copy()
                tampered_blocks[0] ^= 0x0F0F
                decrypted_blocks = self.cbc_mode.decrypt(tampered_blocks, key, iv)

            output = "CBC模式篡改测试:\n\n"
            output += f"原始明文: {' '.join(f'{block:04X}' for block in plaintext_blocks)}\n"
            output += f"正常密文: {' '.join(f'{block:04X}' for block in ciphertext_blocks)}\n"
            output += f"篡改密文: {' '.join(f'{block:04X}' for block in tampered_blocks)}\n"
            output += f"解密结果: {' '.join(f'{block:04X}' for block in decrypted_blocks)}\n\n"
            output += "注意: 在CBC模式下，篡改一个密文分组会影响对应的明文分组和下一个明文分组"

            self.cbc_output.delete(1.0, tk.END)
            self.cbc_output.insert(tk.END, output)

        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制数")

    def clear_cbc(self):
        self.cbc_plaintext_entry.delete(0, tk.END)
        self.cbc_key_entry.delete(0, tk.END)
        self.iv_entry.delete(0, tk.END)
        self.cbc_output.delete(1.0, tk.END)

    def get_enc_type_name(self, enc_type):
        """获取加密类型名称"""
        names = {
            "double": "双重加密 (32位密钥)",
            "triple_32": "三重加密 (32位密钥)",
            "triple_48": "三重加密 (48位密钥)"
        }
        return names.get(enc_type, "未知类型")


def main():
    root = tk.Tk()
    app = SAESGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
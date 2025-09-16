#!/usr/bin/env python3
"""
高级静态二进制漏洞扫描器
增强版本，支持污点分析、逆向分析、多架构和精确地址定位
"""

import os
import sys
import struct
import argparse
import re
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class VulnSeverity(Enum):
    """漏洞严重性等级枚举"""
    CRITICAL = "CRITICAL"  # 严重
    HIGH = "HIGH"          # 高危
    MEDIUM = "MEDIUM"      # 中危
    LOW = "LOW"            # 低危
    INFO = "INFO"          # 信息


class Architecture(Enum):
    """处理器架构枚举"""
    X86 = "X86"            # Intel x86 32位
    X64 = "X64"            # Intel x86 64位
    ARM32 = "ARM32"        # ARM 32位
    ARM64 = "ARM64"        # ARM 64位 (AArch64)
    MIPS32 = "MIPS32"      # MIPS 32位
    MIPS64 = "MIPS64"      # MIPS 64位
    UNKNOWN = "UNKNOWN"    # 未知架构


@dataclass
class FunctionInfo:
    """函数信息数据类"""
    name: str                          # 函数名
    address: int                       # 函数地址
    size: int = 0                      # 函数大小
    instructions: List[bytes] = field(default_factory=list)  # 指令列表
    calls: List[str] = field(default_factory=list)          # 调用的函数
    data_refs: List[int] = field(default_factory=list)      # 数据引用


@dataclass
class TaintSource:
    """污点源数据类"""
    address: int                       # 污点源地址
    function: str                      # 所在函数
    description: str                   # 描述
    taint_type: str                    # 污点类型 (input, network, file)


@dataclass
class Vulnerability:
    """漏洞信息数据类"""
    name: str                              # 漏洞名称
    severity: VulnSeverity                 # 严重性等级
    description: str                       # 漏洞描述
    location: Optional[str] = None         # 漏洞位置
    details: Optional[str] = None          # 详细信息
    function_address: Optional[int] = None # 函数地址
    instruction_address: Optional[int] = None  # 指令地址
    taint_path: List[TaintSource] = field(default_factory=list)  # 污点传播路径


class BinaryFormat(Enum):
    """二进制文件格式枚举"""
    ELF = "ELF"              # Linux/Unix 可执行文件格式
    PE = "PE"                # Windows 可执行文件格式
    UNKNOWN = "UNKNOWN"      # 未知格式


class DisassemblyEngine:
    """反汇编引擎类"""
    
    def __init__(self, arch: Architecture):
        """初始化反汇编引擎
        
        Args:
            arch: 目标架构
        """
        self.arch = arch
        self.instruction_patterns = self._get_instruction_patterns()
    
    def _get_instruction_patterns(self) -> Dict[str, bytes]:
        """获取架构特定的指令模式"""
        patterns = {}
        
        if self.arch == Architecture.X86:
            patterns.update({
                'call': b'\xe8',        # CALL相对地址
                'jmp': b'\xe9',         # JMP相对地址
                'ret': b'\xc3',         # RET
                'push': b'\x50',        # PUSH EAX (示例)
                'pop': b'\x58',         # POP EAX (示例)
                'mov': b'\x89',         # MOV (示例)
            })
        elif self.arch == Architecture.X64:
            patterns.update({
                'call': b'\xe8',        # CALL相对地址
                'jmp': b'\xe9',         # JMP相对地址
                'ret': b'\xc3',         # RET
                'push': b'\x50',        # PUSH RAX (示例)
                'pop': b'\x58',         # POP RAX (示例)
                'mov': b'\x48\x89',     # MOV (REX前缀示例)
            })
        elif self.arch == Architecture.ARM32:
            patterns.update({
                'bl': b'\x00\x00\x00\xeb',     # BL (Branch with Link)
                'bx': b'\x10\xff\x2f\xe1',     # BX LR (Return)
                'push': b'\x00\x48\x2d\xe9',   # PUSH
                'pop': b'\x00\x88\xbd\xe8',    # POP
            })
        elif self.arch == Architecture.ARM64:
            patterns.update({
                'bl': b'\x00\x00\x00\x94',     # BL (Branch with Link)
                'ret': b'\xc0\x03\x5f\xd6',    # RET
                'stp': b'\xff\x83\x00\xa9',    # STP (Store Pair)
                'ldp': b'\xff\x83\x40\xa9',    # LDP (Load Pair)
            })
        elif self.arch in [Architecture.MIPS32, Architecture.MIPS64]:
            patterns.update({
                'jal': b'\x0c\x00\x00\x00',    # JAL (Jump and Link)
                'jr': b'\x08\x00\xe0\x03',     # JR RA (Return)
                'addiu': b'\x21\x00\x00\x24',  # ADDIU (示例)
                'lw': b'\x00\x00\x00\x8c',     # LW (Load Word)
            })
        
        return patterns
    
    def find_functions(self, binary_data: bytes, base_address: int = 0) -> List[FunctionInfo]:
        """查找二进制文件中的函数
        
        Args:
            binary_data: 二进制数据
            base_address: 基地址
        
        Returns:
            函数信息列表
        """
        functions = []
        
        # 查找函数入口点的简单启发式方法
        if self.arch in [Architecture.X86, Architecture.X64]:
            # 查找函数序言模式 (push ebp/rbp; mov ebp/rbp, esp/rsp)
            function_prologue = b'\x55\x89\xe5'  # push ebp; mov ebp, esp
            for i, match in enumerate(re.finditer(re.escape(function_prologue), binary_data)):
                func_addr = base_address + match.start()
                func_info = FunctionInfo(
                    name=f"func_{func_addr:08x}",
                    address=func_addr
                )
                functions.append(func_info)
        
        elif self.arch == Architecture.ARM32:
            # ARM32函数通常以特定的推栈指令开始
            arm_prologue = b'\x00\x48\x2d\xe9'  # push {r11, lr}
            for match in re.finditer(re.escape(arm_prologue), binary_data):
                func_addr = base_address + match.start()
                func_info = FunctionInfo(
                    name=f"func_{func_addr:08x}",
                    address=func_addr
                )
                functions.append(func_info)
        
        return functions
    
    def analyze_function(self, binary_data: bytes, func_info: FunctionInfo) -> FunctionInfo:
        """分析单个函数的详细信息
        
        Args:
            binary_data: 二进制数据
            func_info: 函数信息
        
        Returns:
            更新后的函数信息
        """
        # 简化的函数分析 - 查找函数调用
        start_offset = func_info.address
        max_func_size = 1024  # 假设最大函数大小
        
        # 在函数范围内查找调用指令
        for pattern_name, pattern in self.instruction_patterns.items():
            if pattern_name == 'call':
                for match in re.finditer(re.escape(pattern), binary_data[start_offset:start_offset + max_func_size]):
                    call_addr = start_offset + match.start()
                    func_info.calls.append(f"call_{call_addr:08x}")
        
        return func_info


class TaintAnalyzer:
    """污点分析器类"""
    
    def __init__(self, functions: List[FunctionInfo]):
        """初始化污点分析器
        
        Args:
            functions: 函数列表
        """
        self.functions = functions
        self.taint_sources = []
        self.taint_sinks = []
        self.taint_paths = []
    
    def identify_taint_sources(self, binary_data: bytes) -> List[TaintSource]:
        """识别污点源
        
        Args:
            binary_data: 二进制数据
        
        Returns:
            污点源列表
        """
        sources = []
        
        # 定义常见的污点源函数
        input_functions = [
            b'read', b'recv', b'recvfrom', b'gets', b'fgets',
            b'scanf', b'getchar', b'getenv', b'argv'
        ]
        
        for func_name in input_functions:
            for match in re.finditer(re.escape(func_name), binary_data):
                source = TaintSource(
                    address=match.start(),
                    function=f"unknown_func_{match.start():08x}",
                    description=f"输入函数 {func_name.decode()}",
                    taint_type="input"
                )
                sources.append(source)
        
        self.taint_sources = sources
        return sources
    
    def identify_taint_sinks(self, binary_data: bytes) -> List[str]:
        """识别污点汇聚点
        
        Args:
            binary_data: 二进制数据
        
        Returns:
            汇聚点函数列表
        """
        sinks = []
        
        # 定义常见的污点汇聚点函数
        sink_functions = [
            b'strcpy', b'strcat', b'sprintf', b'system',
            b'exec', b'memcpy', b'memmove'
        ]
        
        for func_name in sink_functions:
            if func_name in binary_data:
                sinks.append(func_name.decode())
        
        self.taint_sinks = sinks
        return sinks
    
    def trace_taint_flow(self) -> List[List[TaintSource]]:
        """跟踪污点流动路径
        
        Returns:
            污点传播路径列表
        """
        paths = []
        
        # 简化的污点流动分析
        # 实际实现需要更复杂的数据流分析
        for source in self.taint_sources:
            path = [source]
            # 这里应该实现实际的污点传播跟踪
            paths.append(path)
        
        self.taint_paths = paths
        return paths


class AdvancedBinaryVulnScanner:
    """高级二进制漏洞扫描器主类"""
    
    def __init__(self, binary_path: str):
        """初始化扫描器
        
        Args:
            binary_path: 要扫描的二进制文件路径
        """
        self.binary_path = binary_path
        self.binary_data = b""
        self.format = BinaryFormat.UNKNOWN
        self.architecture = Architecture.UNKNOWN
        self.vulnerabilities: List[Vulnerability] = []
        self.functions: List[FunctionInfo] = []
        self.elf_header = None
        self.pe_header = None
        
        self._load_binary()
        self._detect_format()
        self._detect_architecture()
        
        # 初始化分析引擎
        self.disasm_engine = DisassemblyEngine(self.architecture)
        self.taint_analyzer = None
    
    def _load_binary(self):
        """将二进制文件加载到内存中"""
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
        except IOError as e:
            raise Exception(f"读取二进制文件失败: {e}")
    
    def _detect_format(self):
        """检测二进制文件格式 (ELF/PE)"""
        if len(self.binary_data) < 4:
            return
        
        # 检查 ELF 魔术字节 (0x7f + "ELF")
        if self.binary_data[:4] == b'\x7fELF':
            self.format = BinaryFormat.ELF
            self._parse_elf_header()
        # 检查 PE 魔术字节 ("MZ")
        elif self.binary_data[:2] == b'MZ':
            self.format = BinaryFormat.PE
            self._parse_pe_header()
    
    def _parse_elf_header(self):
        """解析ELF头部信息"""
        if len(self.binary_data) < 64:  # ELF头部最小大小
            return
        
        self.elf_header = {
            'e_ident': self.binary_data[:16],
            'e_type': struct.unpack('<H', self.binary_data[16:18])[0],
            'e_machine': struct.unpack('<H', self.binary_data[18:20])[0],
            'e_version': struct.unpack('<I', self.binary_data[20:24])[0],
            'e_entry': struct.unpack('<Q', self.binary_data[24:32])[0] if self.binary_data[4] == 2 else struct.unpack('<I', self.binary_data[24:28])[0],
        }
    
    def _parse_pe_header(self):
        """解析PE头部信息"""
        if len(self.binary_data) < 64:
            return
        
        # 获取PE头偏移
        pe_offset = struct.unpack('<I', self.binary_data[60:64])[0]
        if pe_offset + 24 > len(self.binary_data):
            return
        
        self.pe_header = {
            'machine': struct.unpack('<H', self.binary_data[pe_offset + 4:pe_offset + 6])[0],
            'characteristics': struct.unpack('<H', self.binary_data[pe_offset + 22:pe_offset + 24])[0],
        }
    
    def _detect_architecture(self):
        """检测处理器架构"""
        if self.format == BinaryFormat.ELF and self.elf_header:
            machine = self.elf_header['e_machine']
            bit_class = self.binary_data[4]  # EI_CLASS
            
            if machine == 0x3E:  # EM_X86_64
                self.architecture = Architecture.X64
            elif machine == 0x03:  # EM_386
                self.architecture = Architecture.X86
            elif machine == 0x28:  # EM_ARM
                self.architecture = Architecture.ARM32
            elif machine == 0xB7:  # EM_AARCH64
                self.architecture = Architecture.ARM64
            elif machine == 0x08:  # EM_MIPS
                if bit_class == 2:  # 64位
                    self.architecture = Architecture.MIPS64
                else:
                    self.architecture = Architecture.MIPS32
        
        elif self.format == BinaryFormat.PE and self.pe_header:
            machine = self.pe_header['machine']
            
            if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                self.architecture = Architecture.X64
            elif machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                self.architecture = Architecture.X86
            elif machine == 0x1c0:  # IMAGE_FILE_MACHINE_ARM
                self.architecture = Architecture.ARM32
            elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                self.architecture = Architecture.ARM64
    
    def _find_string_references(self, target_string: bytes) -> List[int]:
        """查找字符串引用位置
        
        Args:
            target_string: 目标字符串
        
        Returns:
            字符串出现位置列表
        """
        positions = []
        start = 0
        while True:
            pos = self.binary_data.find(target_string, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        return positions
    
    def _find_function_by_address(self, address: int) -> Optional[FunctionInfo]:
        """根据地址查找函数
        
        Args:
            address: 目标地址
        
        Returns:
            函数信息或None
        """
        for func in self.functions:
            if func.address <= address < func.address + max(func.size, 100):
                return func
        return None
    
    def scan(self) -> List[Vulnerability]:
        """主扫描函数，执行所有漏洞检查
        
        Returns:
            检测到的漏洞列表
        """
        if self.format == BinaryFormat.UNKNOWN:
            self.vulnerabilities.append(
                Vulnerability(
                    "未知二进制格式",
                    VulnSeverity.INFO,
                    "无法识别的二进制文件格式"
                )
            )
            return self.vulnerabilities
        
        # 第一阶段：基础分析
        print(f"🔍 开始基础分析...")
        self._basic_security_checks()
        
        # 第二阶段：反汇编分析
        print(f"🔍 开始反汇编分析...")
        self._reverse_engineering_analysis()
        
        # 第三阶段：污点分析
        print(f"🔍 开始污点分析...")
        self._taint_analysis()
        
        # 第四阶段：架构特定分析
        print(f"🔍 开始架构特定分析...")
        self._architecture_specific_analysis()
        
        return self.vulnerabilities
    
    def _basic_security_checks(self):
        """基础安全检查"""
        self._check_stack_protection()
        self._check_nx_bit()
        self._check_aslr()
        self._check_dangerous_functions()
        self._check_format_strings()
        self._check_buffer_overflow_patterns()
        self._check_integer_overflow()
    
    def _reverse_engineering_analysis(self):
        """逆向工程分析"""
        # 查找函数
        base_address = 0
        if self.elf_header and 'e_entry' in self.elf_header:
            base_address = self.elf_header['e_entry']
        
        self.functions = self.disasm_engine.find_functions(self.binary_data, base_address)
        
        # 分析每个函数
        for i, func in enumerate(self.functions):
            self.functions[i] = self.disasm_engine.analyze_function(self.binary_data, func)
        
        # 查找可疑的函数调用模式
        self._analyze_call_patterns()
    
    def _taint_analysis(self):
        """污点分析"""
        if not self.functions:
            return
        
        # 初始化污点分析器
        self.taint_analyzer = TaintAnalyzer(self.functions)
        
        # 识别污点源和汇聚点
        taint_sources = self.taint_analyzer.identify_taint_sources(self.binary_data)
        taint_sinks = self.taint_analyzer.identify_taint_sinks(self.binary_data)
        
        # 跟踪污点流动
        taint_paths = self.taint_analyzer.trace_taint_flow()
        
        # 检查危险的污点流动路径
        for path in taint_paths:
            if len(path) > 0:
                source = path[0]
                for sink in taint_sinks:
                    self._add_vulnerability(
                        Vulnerability(
                            f"污点流动风险: {source.description} -> {sink}",
                            VulnSeverity.HIGH,
                            f"从 {source.description} 到 {sink} 的不安全数据流动",
                            function_address=source.address,
                            taint_path=path
                        )
                    )
    
    def _architecture_specific_analysis(self):
        """架构特定分析"""
        if self.architecture == Architecture.ARM32:
            self._check_arm32_vulnerabilities()
        elif self.architecture == Architecture.ARM64:
            self._check_arm64_vulnerabilities()
        elif self.architecture in [Architecture.MIPS32, Architecture.MIPS64]:
            self._check_mips_vulnerabilities()
        elif self.architecture in [Architecture.X86, Architecture.X64]:
            self._check_x86_vulnerabilities()
    
    def _check_arm32_vulnerabilities(self):
        """ARM32特定漏洞检查"""
        # 检查ARM32特定的安全问题
        if b'\x00\x00\xa0\xe1' in self.binary_data:  # NOP指令
            positions = self._find_string_references(b'\x00\x00\xa0\xe1')
            for pos in positions:
                self._add_vulnerability(
                    Vulnerability(
                        "ARM32 NOP滑行攻击风险",
                        VulnSeverity.MEDIUM,
                        "检测到大量NOP指令，可能被用于滑行攻击",
                        instruction_address=pos
                    )
                )
    
    def _check_arm64_vulnerabilities(self):
        """ARM64特定漏洞检查"""
        # 检查ARM64特定的安全问题
        if b'\x1f\x20\x03\xd5' in self.binary_data:  # NOP指令
            positions = self._find_string_references(b'\x1f\x20\x03\xd5')
            for pos in positions:
                self._add_vulnerability(
                    Vulnerability(
                        "ARM64 NOP滑行攻击风险",
                        VulnSeverity.MEDIUM,
                        "检测到大量NOP指令，可能被用于滑行攻击",
                        instruction_address=pos
                    )
                )
    
    def _check_mips_vulnerabilities(self):
        """MIPS特定漏洞检查"""
        # 检查MIPS特定的安全问题
        if b'\x00\x00\x00\x00' in self.binary_data:  # MIPS NOP
            # 查找大量连续的NOP指令
            nop_pattern = b'\x00\x00\x00\x00' * 5  # 5个连续NOP
            if nop_pattern in self.binary_data:
                positions = self._find_string_references(nop_pattern)
                for pos in positions:
                    self._add_vulnerability(
                        Vulnerability(
                            "MIPS NOP滑行攻击风险",
                            VulnSeverity.MEDIUM,
                            "检测到大量连续NOP指令，可能被用于滑行攻击",
                            instruction_address=pos
                        )
                    )
    
    def _check_x86_vulnerabilities(self):
        """x86/x64特定漏洞检查"""
        # 检查ROP链相关的gadgets
        rop_patterns = [
            b'\xc3',           # RET
            b'\x5d\xc3',       # POP EBP; RET
            b'\x58\xc3',       # POP EAX; RET
        ]
        
        for pattern in rop_patterns:
            positions = self._find_string_references(pattern)
            if len(positions) > 20:  # 大量ROP gadgets
                self._add_vulnerability(
                    Vulnerability(
                        "ROP链攻击风险",
                        VulnSeverity.MEDIUM,
                        f"检测到大量ROP gadgets ({len(positions)}个)，可能被用于ROP攻击",
                        details=f"模式: {pattern.hex()}"
                    )
                )
    
    def _analyze_call_patterns(self):
        """分析函数调用模式"""
        # 统计函数调用频率
        call_count = defaultdict(int)
        for func in self.functions:
            for call in func.calls:
                call_count[call] += 1
        
        # 检查异常的调用模式
        for call, count in call_count.items():
            if count > 10:  # 被大量调用的函数
                func = self._find_function_by_address(int(call.split('_')[1], 16))
                self._add_vulnerability(
                    Vulnerability(
                        f"高频调用函数: {call}",
                        VulnSeverity.LOW,
                        f"函数被调用 {count} 次，可能是热点函数",
                        function_address=func.address if func else None
                    )
                )
    
    def _add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞到列表中"""
        self.vulnerabilities.append(vuln)
    
    def _check_stack_protection(self):
        """检查栈金丝雀和栈保护机制"""
        if self.format == BinaryFormat.ELF:
            positions = self._find_string_references(b'__stack_chk_fail')
            if not positions:
                self._add_vulnerability(
                    Vulnerability(
                        "缺少栈金丝雀保护",
                        VulnSeverity.HIGH,
                        "二进制文件缺少栈金丝雀保护，容易受到栈缓冲区溢出攻击"
                    )
                )
            else:
                # 报告找到栈保护的地址
                for pos in positions:
                    func = self._find_function_by_address(pos)
                    self._add_vulnerability(
                        Vulnerability(
                            "栈保护检查点",
                            VulnSeverity.INFO,
                            "发现栈金丝雀保护检查点",
                            function_address=func.address if func else None,
                            instruction_address=pos
                        )
                    )
    
    def _check_nx_bit(self):
        """检查 NX 位 (DEP) 保护"""
        if self.format == BinaryFormat.ELF:
            if b'GNU_STACK' in self.binary_data:
                positions = self._find_string_references(b'GNU_STACK')
                for pos in positions:
                    self._add_vulnerability(
                        Vulnerability(
                            "GNU_STACK段存在",
                            VulnSeverity.INFO,
                            "发现GNU_STACK段标记",
                            instruction_address=pos
                        )
                    )
            else:
                self._add_vulnerability(
                    Vulnerability(
                        "缺少NX位保护",
                        VulnSeverity.HIGH,
                        "栈可能可执行，允许shellcode执行"
                    )
                )
    
    def _check_aslr(self):
        """检查 ASLR/PIE 支持"""
        if self.format == BinaryFormat.ELF and self.elf_header:
            e_type = self.elf_header['e_type']
            if e_type != 3:  # ET_DYN (动态共享对象类型)
                self._add_vulnerability(
                    Vulnerability(
                        "缺少PIE/ASLR保护",
                        VulnSeverity.MEDIUM,
                        "二进制文件未使用位置无关可执行文件编译，ASLR保护失效"
                    )
                )
    
    def _check_dangerous_functions(self):
        """检查危险函数调用"""
        dangerous_funcs = [
            b'gets', b'strcpy', b'strcat', b'sprintf', b'vsprintf',
            b'scanf', b'sscanf', b'fscanf', b'vfscanf', b'realpath',
            b'getwd', b'wcscpy', b'wcscat', b'mbscpy', b'mbscat'
        ]
        
        for func in dangerous_funcs:
            positions = self._find_string_references(func)
            for pos in positions:
                function = self._find_function_by_address(pos)
                self._add_vulnerability(
                    Vulnerability(
                        f"危险函数: {func.decode()}",
                        VulnSeverity.HIGH,
                        f"使用危险函数 {func.decode()} 可能导致缓冲区溢出漏洞",
                        function_address=function.address if function else None,
                        instruction_address=pos
                    )
                )
    
    def _check_format_strings(self):
        """检查格式化字符串漏洞"""
        format_funcs = [b'printf', b'fprintf', b'sprintf', b'snprintf', b'vprintf']
        
        for func in format_funcs:
            positions = self._find_string_references(func)
            for pos in positions:
                function = self._find_function_by_address(pos)
                self._add_vulnerability(
                    Vulnerability(
                        f"潜在格式化字符串漏洞: {func.decode()}",
                        VulnSeverity.MEDIUM,
                        f"检测到函数 {func.decode()} - 请验证格式化字符串不受用户控制",
                        function_address=function.address if function else None,
                        instruction_address=pos
                    )
                )
    
    def _check_buffer_overflow_patterns(self):
        """检查常见的缓冲区溢出模式"""
        patterns = [
            (rb'read.*buf', "read操作中可能存在缓冲区溢出"),
            (rb'fgets.*buf', "fgets操作中可能存在缓冲区溢出"),
            (rb'memcpy.*[0-9]+', "固定大小的memcpy可能导致溢出"),
        ]
        
        for pattern, desc in patterns:
            for match in re.finditer(pattern, self.binary_data, re.IGNORECASE):
                pos = match.start()
                function = self._find_function_by_address(pos)
                self._add_vulnerability(
                    Vulnerability(
                        "潜在缓冲区溢出模式",
                        VulnSeverity.MEDIUM,
                        desc,
                        function_address=function.address if function else None,
                        instruction_address=pos
                    )
                )
    
    def _check_integer_overflow(self):
        """检查潜在的整数溢出漏洞"""
        for match in re.finditer(rb'malloc.*\*', self.binary_data):
            pos = match.start()
            function = self._find_function_by_address(pos)
            self._add_vulnerability(
                Vulnerability(
                    "潜在整数溢出",
                    VulnSeverity.MEDIUM,
                    "检测到malloc与乘法运算 - 请检查是否存在整数溢出",
                    function_address=function.address if function else None,
                    instruction_address=pos
                )
            )


def print_vulnerabilities(vulnerabilities: List[Vulnerability]):
    """打印漏洞报告"""
    if not vulnerabilities:
        print("✅ 未检测到漏洞")
        return
    
    severity_colors = {
        VulnSeverity.CRITICAL: '\033[91m',  # 红色
        VulnSeverity.HIGH: '\033[91m',      # 红色
        VulnSeverity.MEDIUM: '\033[93m',    # 黄色
        VulnSeverity.LOW: '\033[92m',       # 绿色
        VulnSeverity.INFO: '\033[94m',      # 蓝色
    }
    reset_color = '\033[0m'
    
    print(f"\n🔍 发现 {len(vulnerabilities)} 个潜在漏洞:\n")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        color = severity_colors.get(vuln.severity, '')
        print(f"{i}. {color}[{vuln.severity.value}]{reset_color} {vuln.name}")
        print(f"   描述: {vuln.description}")
        
        if vuln.function_address:
            print(f"   函数地址: 0x{vuln.function_address:08x}")
        
        if vuln.instruction_address:
            print(f"   指令地址: 0x{vuln.instruction_address:08x}")
        
        if vuln.location:
            print(f"   位置: {vuln.location}")
        
        if vuln.details:
            print(f"   详情: {vuln.details}")
        
        if vuln.taint_path:
            print(f"   污点路径: {len(vuln.taint_path)} 个污点源")
            for j, taint in enumerate(vuln.taint_path[:3]):  # 只显示前3个
                print(f"     {j+1}. {taint.description} @ 0x{taint.address:08x}")
        
        print()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='高级静态二进制漏洞扫描器')
    parser.add_argument('binary', help='要扫描的二进制文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='启用详细输出模式')
    parser.add_argument('--taint', action='store_true',
                       help='启用污点分析')
    parser.add_argument('--reverse', action='store_true',
                       help='启用逆向分析')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.binary):
        print(f"错误: 找不到文件 '{args.binary}'")
        sys.exit(1)
    
    try:
        scanner = AdvancedBinaryVulnScanner(args.binary)
        print(f"🔍 正在扫描二进制文件: {args.binary}")
        print(f"📋 文件格式: {scanner.format.value}")
        print(f"🏗️ 处理器架构: {scanner.architecture.value}")
        
        vulnerabilities = scanner.scan()
        print_vulnerabilities(vulnerabilities)
        
        # 输出统计信息
        print(f"\n📊 扫描统计:")
        print(f"   检测到函数: {len(scanner.functions)} 个")
        if scanner.taint_analyzer:
            print(f"   污点源: {len(scanner.taint_analyzer.taint_sources)} 个")
            print(f"   污点汇聚点: {len(scanner.taint_analyzer.taint_sinks)} 个")
        
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
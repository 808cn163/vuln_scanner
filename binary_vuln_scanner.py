#!/usr/bin/env python3
"""
静态二进制漏洞扫描器
用于检测二进制可执行文件中常见漏洞的工具
"""

import os
import sys
import struct
import argparse
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class VulnSeverity(Enum):
    """漏洞严重性等级枚举"""
    CRITICAL = "CRITICAL"  # 严重
    HIGH = "HIGH"          # 高危
    MEDIUM = "MEDIUM"      # 中危
    LOW = "LOW"            # 低危
    INFO = "INFO"          # 信息


@dataclass
class Vulnerability:
    """漏洞信息数据类"""
    name: str                              # 漏洞名称
    severity: VulnSeverity                 # 严重性等级
    description: str                       # 漏洞描述
    location: Optional[str] = None         # 漏洞位置
    details: Optional[str] = None          # 详细信息


class BinaryFormat(Enum):
    """二进制文件格式枚举"""
    ELF = "ELF"              # Linux/Unix 可执行文件格式
    PE = "PE"                # Windows 可执行文件格式
    UNKNOWN = "UNKNOWN"      # 未知格式


class BinaryVulnScanner:
    """二进制漏洞扫描器主类"""
    
    def __init__(self, binary_path: str):
        """初始化扫描器
        
        Args:
            binary_path: 要扫描的二进制文件路径
        """
        self.binary_path = binary_path                    # 二进制文件路径
        self.binary_data = b""                           # 二进制文件数据
        self.format = BinaryFormat.UNKNOWN               # 文件格式
        self.vulnerabilities: List[Vulnerability] = []   # 发现的漏洞列表
        
        self._load_binary()    # 加载二进制文件
        self._detect_format()  # 检测文件格式
    
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
        # 检查 PE 魔术字节 ("MZ")
        elif self.binary_data[:2] == b'MZ':
            self.format = BinaryFormat.PE
    
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
        
        # 执行所有漏洞检查
        self._check_stack_protection()        # 栈保护检查
        self._check_nx_bit()                  # NX位检查
        self._check_aslr()                    # ASLR检查
        self._check_dangerous_functions()     # 危险函数检查
        self._check_format_strings()          # 格式化字符串检查
        self._check_buffer_overflow_patterns() # 缓冲区溢出模式检查
        self._check_integer_overflow()        # 整数溢出检查
        
        return self.vulnerabilities
    
    def _add_vulnerability(self, vuln: Vulnerability):
        """添加漏洞到列表中
        
        Args:
            vuln: 要添加的漏洞信息
        """
        self.vulnerabilities.append(vuln)
    
    def _check_stack_protection(self):
        """检查栈金丝雀和栈保护机制"""
        if self.format == BinaryFormat.ELF:
            # 检查是否存在栈金丝雀保护函数
            if b'__stack_chk_fail' not in self.binary_data:
                self._add_vulnerability(
                    Vulnerability(
                        "缺少栈金丝雀保护",
                        VulnSeverity.HIGH,
                        "二进制文件缺少栈金丝雀保护，容易受到栈缓冲区溢出攻击"
                    )
                )
    
    def _check_nx_bit(self):
        """检查 NX 位 (DEP) 保护"""
        if self.format == BinaryFormat.ELF:
            # 检查 GNU_STACK 段标记
            if b'GNU_STACK' in self.binary_data:
                # 简单启发式检查 - 需要更详细的解析
                pass
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
        if self.format == BinaryFormat.ELF:
            # 检查 ELF 头部的 PIE 支持
            if len(self.binary_data) >= 16:
                e_type = struct.unpack('<H', self.binary_data[16:18])[0]
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
        # 定义危险函数列表 - 这些函数容易导致缓冲区溢出
        dangerous_funcs = [
            b'gets', b'strcpy', b'strcat', b'sprintf', b'vsprintf',
            b'scanf', b'sscanf', b'fscanf', b'vfscanf', b'realpath',
            b'getwd', b'wcscpy', b'wcscat', b'mbscpy', b'mbscat'
        ]
        
        # 检查二进制文件中是否包含这些危险函数
        for func in dangerous_funcs:
            if func in self.binary_data:
                self._add_vulnerability(
                    Vulnerability(
                        f"危险函数: {func.decode()}",
                        VulnSeverity.HIGH,
                        f"使用危险函数 {func.decode()} 可能导致缓冲区溢出漏洞"
                    )
                )
    
    def _check_format_strings(self):
        """检查格式化字符串漏洞"""
        # 查找 printf 系列函数，可能存在用户控制的格式化字符串
        format_funcs = [b'printf', b'fprintf', b'sprintf', b'snprintf', b'vprintf']
        
        for func in format_funcs:
            if func in self.binary_data:
                # 这是基础检查 - 更复杂的分析需要跟踪数据流
                self._add_vulnerability(
                    Vulnerability(
                        f"潜在格式化字符串漏洞: {func.decode()}",
                        VulnSeverity.MEDIUM,
                        f"检测到函数 {func.decode()} - 请验证格式化字符串不受用户控制"
                    )
                )
    
    def _check_buffer_overflow_patterns(self):
        """检查常见的缓冲区溢出模式"""
        # 查找可能指示缓冲区溢出漏洞的模式
        patterns = [
            (rb'read.*buf', "read操作中可能存在缓冲区溢出"),
            (rb'fgets.*buf', "fgets操作中可能存在缓冲区溢出"),
            (rb'memcpy.*[0-9]+', "固定大小的memcpy可能导致溢出"),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, self.binary_data, re.IGNORECASE):
                self._add_vulnerability(
                    Vulnerability(
                        "潜在缓冲区溢出模式",
                        VulnSeverity.MEDIUM,
                        desc
                    )
                )
    
    def _check_integer_overflow(self):
        """检查潜在的整数溢出漏洞"""
        # 查找带有算术运算的 malloc 调用
        if re.search(rb'malloc.*\*', self.binary_data):
            self._add_vulnerability(
                Vulnerability(
                    "潜在整数溢出",
                    VulnSeverity.MEDIUM,
                    "检测到malloc与乘法运算 - 请检查是否存在整数溢出"
                )
            )


def print_vulnerabilities(vulnerabilities: List[Vulnerability]):
    """打印漏洞报告
    
    Args:
        vulnerabilities: 漏洞列表
    """
    if not vulnerabilities:
        print("✅ 未检测到漏洞")
        return
    
    # 定义严重性等级的颜色
    severity_colors = {
        VulnSeverity.CRITICAL: '\033[91m',  # 红色
        VulnSeverity.HIGH: '\033[91m',      # 红色
        VulnSeverity.MEDIUM: '\033[93m',    # 黄色
        VulnSeverity.LOW: '\033[92m',       # 绿色
        VulnSeverity.INFO: '\033[94m',      # 蓝色
    }
    reset_color = '\033[0m'
    
    print(f"\n🔍 发现 {len(vulnerabilities)} 个潜在漏洞:\n")
    
    # 逐个打印漏洞信息
    for i, vuln in enumerate(vulnerabilities, 1):
        color = severity_colors.get(vuln.severity, '')
        print(f"{i}. {color}[{vuln.severity.value}]{reset_color} {vuln.name}")
        print(f"   描述: {vuln.description}")
        if vuln.location:
            print(f"   位置: {vuln.location}")
        if vuln.details:
            print(f"   详情: {vuln.details}")
        print()


def main():
    """主函数 - 程序入口点"""
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description='静态二进制漏洞扫描器')
    parser.add_argument('binary', help='要扫描的二进制文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='启用详细输出模式')
    
    args = parser.parse_args()
    
    # 检查文件是否存在
    if not os.path.exists(args.binary):
        print(f"错误: 找不到文件 '{args.binary}'")
        sys.exit(1)
    
    try:
        # 创建扫描器实例并执行扫描
        scanner = BinaryVulnScanner(args.binary)
        print(f"🔍 正在扫描二进制文件: {args.binary}")
        print(f"📋 文件格式: {scanner.format.value}")
        
        # 执行漏洞扫描并打印结果
        vulnerabilities = scanner.scan()
        print_vulnerabilities(vulnerabilities)
        
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()  # 运行主函数
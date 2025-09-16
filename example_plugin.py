#!/usr/bin/env python3
"""
示例插件 - 演示如何创建自定义漏洞检测插件
"""

from enterprise_binary_vuln_scanner import (
    Plugin, Vulnerability, VulnSeverity, 
    BinaryFormat, Architecture, VulnCategoryRegistry
)
import re
from typing import List


class ExampleVulnerabilityPlugin(Plugin):
    """示例漏洞检测插件"""
    
    def get_name(self) -> str:
        return "示例漏洞检测插件"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes, format_type: BinaryFormat, 
               arch: Architecture) -> List[Vulnerability]:
        """执行分析"""
        vulnerabilities = []
        
        # 示例1: 检测硬编码密码
        hardcoded_passwords = self._check_hardcoded_passwords(binary_data)
        vulnerabilities.extend(hardcoded_passwords)
        
        # 示例2: 检测弱加密算法
        weak_crypto = self._check_weak_crypto(binary_data)
        vulnerabilities.extend(weak_crypto)
        
        # 示例3: 检测调试信息泄露
        debug_info = self._check_debug_info_leak(binary_data)
        vulnerabilities.extend(debug_info)
        
        return vulnerabilities
    
    def _check_hardcoded_passwords(self, binary_data: bytes) -> List[Vulnerability]:
        """检测硬编码密码"""
        vulnerabilities = []
        
        # 常见的密码模式
        password_patterns = [
            rb'password\s*=\s*["\'][^"\']{8,}["\']',
            rb'passwd\s*=\s*["\'][^"\']{8,}["\']',
            rb'pwd\s*=\s*["\'][^"\']{8,}["\']',
            rb'secret\s*=\s*["\'][^"\']{8,}["\']',
            rb'key\s*=\s*["\'][^"\']{16,}["\']'
        ]
        
        for pattern in password_patterns:
            matches = re.finditer(pattern, binary_data, re.IGNORECASE)
            for match in matches:
                vulnerabilities.append(
                    Vulnerability(
                        "硬编码密码",
                        VulnSeverity.HIGH,
                        "检测到可能的硬编码密码或密钥，存在信息泄露风险",
                        category=VulnCategoryRegistry.get_category("injection"),
                        instruction_address=match.start(),
                        confidence=0.8
                    )
                )
        
        return vulnerabilities
    
    def _check_weak_crypto(self, binary_data: bytes) -> List[Vulnerability]:
        """检测弱加密算法"""
        vulnerabilities = []
        
        # 弱加密算法标识
        weak_crypto_patterns = [
            (rb'MD5', "MD5哈希算法已被破解，不应用于安全场景"),
            (rb'SHA1', "SHA1哈希算法存在碰撞攻击风险"),
            (rb'DES', "DES加密算法密钥长度过短，容易被暴力破解"),
            (rb'RC4', "RC4流密码存在已知安全漏洞"),
            (rb'ECB', "ECB模式不提供适当的数据保护")
        ]
        
        for pattern, description in weak_crypto_patterns:
            if pattern in binary_data:
                positions = []
                start = 0
                while True:
                    pos = binary_data.find(pattern, start)
                    if pos == -1:
                        break
                    positions.append(pos)
                    start = pos + 1
                
                for pos in positions:
                    vulnerabilities.append(
                        Vulnerability(
                            f"弱加密算法: {pattern.decode()}",
                            VulnSeverity.MEDIUM,
                            description,
                            instruction_address=pos,
                            confidence=0.9
                        )
                    )
        
        return vulnerabilities
    
    def _check_debug_info_leak(self, binary_data: bytes) -> List[Vulnerability]:
        """检测调试信息泄露"""
        vulnerabilities = []
        
        # 调试信息模式
        debug_patterns = [
            rb'__FILE__',
            rb'__LINE__',
            rb'__FUNCTION__',
            rb'printf\s*\(\s*"DEBUG',
            rb'fprintf\s*\(\s*stderr',
            rb'std::cout\s*<<.*DEBUG'
        ]
        
        debug_count = 0
        for pattern in debug_patterns:
            matches = list(re.finditer(pattern, binary_data, re.IGNORECASE))
            debug_count += len(matches)
        
        if debug_count > 5:  # 如果发现多个调试信息
            vulnerabilities.append(
                Vulnerability(
                    "调试信息泄露",
                    VulnSeverity.LOW,
                    f"二进制文件包含 {debug_count} 处调试信息，可能泄露敏感信息",
                    confidence=0.7
                )
            )
        
        return vulnerabilities


class BufferOverflowEnhancedPlugin(Plugin):
    """增强的缓冲区溢出检测插件"""
    
    def get_name(self) -> str:
        return "增强缓冲区溢出检测"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def analyze(self, binary_data: bytes, format_type: BinaryFormat, 
               arch: Architecture) -> List[Vulnerability]:
        """执行分析"""
        vulnerabilities = []
        
        # 检测更多危险函数
        dangerous_functions = [
            (rb'stpcpy', "stpcpy函数不检查目标缓冲区大小"),
            (rb'wcscpy', "wcscpy函数不检查目标缓冲区大小"),
            (rb'lstrcpy', "lstrcpy函数不检查目标缓冲区大小"),
            (rb'StrCpy', "StrCpy函数不检查目标缓冲区大小"),
            (rb'memccpy', "memccpy函数在某些情况下可能导致溢出"),
            (rb'bcopy', "bcopy函数不检查缓冲区大小"),
        ]
        
        for func_pattern, description in dangerous_functions:
            positions = []
            start = 0
            while True:
                pos = binary_data.find(func_pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            for pos in positions:
                vulnerabilities.append(
                    Vulnerability(
                        f"危险函数: {func_pattern.decode()}",
                        VulnSeverity.HIGH,
                        description,
                        category=VulnCategoryRegistry.get_category("buffer_overflow"),
                        instruction_address=pos,
                        confidence=0.95
                    )
                )
        
        # 检测潜在的缓冲区大小模式
        buffer_patterns = [
            rb'char\s+\w+\[(\d+)\]',  # char buffer[size]
            rb'malloc\s*\(\s*(\d+)\s*\)',  # malloc(size)
            rb'alloca\s*\(\s*(\d+)\s*\)'   # alloca(size)
        ]
        
        for pattern in buffer_patterns:
            matches = re.finditer(pattern, binary_data)
            for match in matches:
                try:
                    size = int(match.group(1))
                    if size < 8:  # 非常小的缓冲区
                        vulnerabilities.append(
                            Vulnerability(
                                "小缓冲区风险",
                                VulnSeverity.MEDIUM,
                                f"检测到大小为 {size} 的小缓冲区，容易溢出",
                                instruction_address=match.start(),
                                confidence=0.6
                            )
                        )
                except (ValueError, IndexError):
                    pass
        
        return vulnerabilities


# 插件注册示例
def register_plugins(plugin_manager):
    """注册插件到插件管理器"""
    plugin_manager.register_plugin(ExampleVulnerabilityPlugin())
    plugin_manager.register_plugin(BufferOverflowEnhancedPlugin())


if __name__ == "__main__":
    # 测试插件
    test_data = b'''
    char password = "hardcoded123";
    char buffer[4];
    strcpy(buffer, user_input);
    MD5_Update(&ctx, data, len);
    printf("DEBUG: %s\\n", __FILE__);
    '''
    
    plugin = ExampleVulnerabilityPlugin()
    vulnerabilities = plugin.analyze(test_data, BinaryFormat.ELF, Architecture.X64)
    
    print(f"插件 {plugin.get_name()} v{plugin.get_version()}")
    print(f"发现 {len(vulnerabilities)} 个漏洞:")
    
    for vuln in vulnerabilities:
        print(f"- {vuln.name}: {vuln.description}")
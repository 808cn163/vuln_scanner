#!/usr/bin/env python3
"""
演示脚本 - 展示企业级二进制漏洞扫描器的功能
"""

import os
import sys
import tempfile
from enterprise_binary_vuln_scanner import EnterpriseBinaryVulnScanner


def create_demo_binary():
    """创建演示用的二进制文件"""
    # 创建一个包含多种漏洞的C代码示例
    vulnerable_code = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char global_password[] = "admin123";

void vulnerable_function(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // 缓冲区溢出
    printf(input);          // 格式化字符串漏洞
}

int main(int argc, char* argv[]) {
    char* data = malloc(argc * sizeof(char));  // 潜在整数溢出
    
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    
    gets(data);  // 危险函数
    
    printf("Password: %s\\n", global_password);
    
    free(data);
    return 0;
}
"""
    
    # 将代码写入临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(vulnerable_code)
        c_file = f.name
    
    # 编译为二进制文件（如果有gcc）
    binary_file = c_file.replace('.c', '')
    compile_cmd = f"gcc -o {binary_file} {c_file} 2>/dev/null"
    
    if os.system(compile_cmd) == 0:
        print(f"✅ 创建演示二进制文件: {binary_file}")
        return binary_file
    else:
        print("⚠️  无法编译演示文件，将使用模拟数据")
        # 创建模拟的二进制数据
        mock_binary_data = (
            b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # ELF头
            b'strcpy\x00gets\x00printf\x00malloc\x00'  # 危险函数
            b'admin123\x00'  # 硬编码密码
            b'MD5\x00SHA1\x00'  # 弱加密算法
            b'__FILE__\x00DEBUG\x00'  # 调试信息
            b'\x00' * 100  # 填充数据
        )
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(mock_binary_data)
            return f.name


def demo_single_file_scan():
    """演示单文件扫描"""
    print("\n" + "="*60)
    print("🔍 单文件扫描演示")
    print("="*60)
    
    # 创建演示文件
    demo_file = create_demo_binary()
    
    try:
        # 初始化扫描器
        scanner = EnterpriseBinaryVulnScanner()
        
        # 执行扫描
        print(f"\n正在扫描文件: {demo_file}")
        vulnerabilities, metadata = scanner.scan_file(
            demo_file,
            enable_symbolic=True,
            enable_dataflow=True
        )
        
        # 显示结果
        print(f"\n📊 扫描结果:")
        print(f"   文件格式: {metadata.get('format', 'Unknown')}")
        print(f"   处理器架构: {metadata.get('architecture', 'Unknown')}")
        print(f"   文件大小: {metadata.get('file_size', 0)} 字节")
        print(f"   发现漏洞: {len(vulnerabilities)} 个")
        
        # 显示漏洞详情
        if vulnerabilities:
            print(f"\n🛡️ 漏洞详情:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):  # 只显示前5个
                print(f"\n{i}. [{vuln.severity.value}] {vuln.name}")
                print(f"   描述: {vuln.description}")
                if vuln.function_address:
                    print(f"   函数地址: 0x{vuln.function_address:08x}")
                if vuln.fix_suggestions:
                    print(f"   修复建议: {vuln.fix_suggestions[0].description}")
        
        # 生成报告
        print(f"\n📋 生成报告...")
        report_files = scanner.generate_reports(
            vulnerabilities, demo_file, metadata, ['json', 'html']
        )
        
        for report_file in report_files:
            print(f"   ✅ 报告已生成: {report_file}")
    
    finally:
        # 清理临时文件
        if os.path.exists(demo_file):
            os.unlink(demo_file)


def demo_batch_scan():
    """演示批量扫描"""
    print("\n" + "="*60)
    print("🔍 批量扫描演示")
    print("="*60)
    
    # 创建临时目录和多个演示文件
    temp_dir = tempfile.mkdtemp()
    demo_files = []
    
    try:
        # 创建多个演示文件
        for i in range(3):
            demo_file = create_demo_binary()
            new_path = os.path.join(temp_dir, f"demo_binary_{i}")
            os.rename(demo_file, new_path)
            demo_files.append(new_path)
        
        print(f"\n创建了 {len(demo_files)} 个演示文件在目录: {temp_dir}")
        
        # 初始化扫描器
        scanner = EnterpriseBinaryVulnScanner()
        
        # 执行批量扫描
        print(f"\n正在批量扫描目录...")
        results = scanner.scan_directory(temp_dir, max_workers=2)
        
        # 统计结果
        total_vulns = 0
        for file_path, (vulnerabilities, metadata) in results.items():
            total_vulns += len(vulnerabilities)
        
        print(f"\n📊 批量扫描结果:")
        print(f"   扫描文件: {len(results)} 个")
        print(f"   总漏洞数: {total_vulns} 个")
        
        # 显示每个文件的结果
        for file_path, (vulnerabilities, metadata) in results.items():
            filename = os.path.basename(file_path)
            print(f"\n   📁 {filename}: {len(vulnerabilities)} 个漏洞")
            
            # 显示前2个漏洞
            for vuln in vulnerabilities[:2]:
                print(f"      • [{vuln.severity.value}] {vuln.name}")
        
        # 生成汇总报告
        all_vulnerabilities = []
        for vulnerabilities, _ in results.values():
            all_vulnerabilities.extend(vulnerabilities)
        
        if all_vulnerabilities:
            print(f"\n📋 生成汇总报告...")
            summary_metadata = {
                "scan_type": "batch",
                "total_files": len(results),
                "total_vulnerabilities": len(all_vulnerabilities)
            }
            
            report_files = scanner.generate_reports(
                all_vulnerabilities, temp_dir, summary_metadata, ['json']
            )
            
            for report_file in report_files:
                print(f"   ✅ 汇总报告已生成: {report_file}")
    
    finally:
        # 清理临时文件
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def demo_plugin_system():
    """演示插件系统"""
    print("\n" + "="*60)
    print("🔌 插件系统演示")
    print("="*60)
    
    try:
        from example_plugin import ExampleVulnerabilityPlugin, BufferOverflowEnhancedPlugin
        
        # 创建演示数据
        test_data = b'''
        char password[] = "hardcoded123";
        char buffer[4];
        strcpy(buffer, user_input);
        MD5_Update(&ctx, data, len);
        printf("DEBUG: %s\\n", __FILE__);
        gets(user_input);
        '''
        
        # 测试插件
        plugins = [
            ExampleVulnerabilityPlugin(),
            BufferOverflowEnhancedPlugin()
        ]
        
        print("\n🔌 加载的插件:")
        for plugin in plugins:
            print(f"   • {plugin.get_name()} v{plugin.get_version()}")
        
        print(f"\n🔍 插件分析结果:")
        total_vulns = 0
        
        for plugin in plugins:
            from enterprise_binary_vuln_scanner import BinaryFormat, Architecture
            
            vulnerabilities = plugin.analyze(
                test_data, 
                BinaryFormat.ELF, 
                Architecture.X64
            )
            
            print(f"\n   📋 {plugin.get_name()}:")
            print(f"      发现漏洞: {len(vulnerabilities)} 个")
            
            for vuln in vulnerabilities:
                print(f"      • [{vuln.severity.value}] {vuln.name}")
                print(f"        {vuln.description}")
            
            total_vulns += len(vulnerabilities)
        
        print(f"\n📊 插件系统总计发现: {total_vulns} 个漏洞")
    
    except ImportError as e:
        print(f"⚠️  无法加载插件: {e}")


def demo_visualization():
    """演示可视化功能"""
    print("\n" + "="*60)
    print("📊 可视化功能演示")
    print("="*60)
    
    try:
        from enterprise_binary_vuln_scanner import FunctionInfo, VisualizationGenerator
        
        # 创建模拟函数信息
        functions = [
            FunctionInfo("main", 0x401000, 100, calls=["func1", "func2"]),
            FunctionInfo("func1", 0x401100, 50, calls=["helper"]),
            FunctionInfo("func2", 0x401200, 80, calls=["helper", "func3"]),
            FunctionInfo("func3", 0x401300, 30, calls=[]),
            FunctionInfo("helper", 0x401400, 20, calls=[])
        ]
        
        # 生成可视化
        viz_gen = VisualizationGenerator()
        
        print("\n📊 生成调用图...")
        call_graph_file = viz_gen.generate_call_graph(functions)
        if call_graph_file:
            print(f"   ✅ 调用图已生成: {call_graph_file}")
            print(f"   💡 使用 Graphviz 查看: dot -Tpng {call_graph_file} -o call_graph.png")
        
        print(f"\n📊 生成控制流图...")
        for func in functions[:2]:  # 为前2个函数生成CFG
            cfg_file = viz_gen.generate_control_flow_graph(func)
            if cfg_file:
                print(f"   ✅ {func.name} 控制流图: {cfg_file}")
    
    except Exception as e:
        print(f"⚠️  可视化生成失败: {e}")


def main():
    """主演示函数"""
    print("🔍 企业级二进制漏洞扫描器演示")
    print("=" * 60)
    
    try:
        # 1. 单文件扫描演示
        demo_single_file_scan()
        
        # 2. 批量扫描演示
        demo_batch_scan()
        
        # 3. 插件系统演示
        demo_plugin_system()
        
        # 4. 可视化功能演示
        demo_visualization()
        
        print("\n" + "="*60)
        print("✅ 演示完成！")
        print("\n💡 提示:")
        print("   • 使用 python3 enterprise_binary_vuln_scanner.py --help 查看完整选项")
        print("   • 使用 python3 gui_scanner.py 启动图形界面")
        print("   • 查看生成的报告文件了解详细结果")
        print("="*60)
    
    except KeyboardInterrupt:
        print("\n❌ 演示被用户中断")
    except Exception as e:
        print(f"\n❌ 演示过程中发生错误: {e}")


if __name__ == "__main__":
    main()
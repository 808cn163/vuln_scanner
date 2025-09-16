#!/usr/bin/env python3
"""
图形界面二进制漏洞扫描器
基于tkinter的用户友好界面
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import sys
from typing import List, Dict, Any
import time
import shutil
import tempfile
import subprocess
import logging

# 设置日志
logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("PIL not available, image display will be limited")

# 导入企业级扫描器
try:
    from enterprise_binary_vuln_scanner import (
        EnterpriseBinaryVulnScanner, 
        Vulnerability, 
        VulnSeverity,
        VulnCategory,
        FunctionInfo
    )
    SCANNER_TYPE = "enterprise"
except ImportError:
    print("警告: 无法导入企业级扫描器，将使用高级扫描器")
    try:
        from advanced_binary_vuln_scanner import (
            AdvancedBinaryVulnScanner as EnterpriseBinaryVulnScanner,
            Vulnerability,
            VulnSeverity
        )
        SCANNER_TYPE = "advanced"
    except ImportError:
        print("警告: 无法导入高级扫描器，将使用基础扫描器")
        try:
            from binary_vuln_scanner import (
                BinaryVulnScanner as EnterpriseBinaryVulnScanner,
                Vulnerability,
                VulnSeverity
            )
            SCANNER_TYPE = "basic"
        except ImportError:
            print("错误: 无法导入任何扫描器模块")
            sys.exit(1)


class CWEDatabase:
    """CWE漏洞数据库"""
    
    cwe_templates = {
        "CWE-119": {
            "name": "缓冲区边界内存访问不当",
            "description": "软件对缓冲区内存的读写操作没有正确限制在有效边界内",
            "severity": "HIGH",
            "category": "内存安全",
            "detection_patterns": ["strcpy", "strcat", "gets", "sprintf"],
            "mitigation": "使用边界检查函数如strncpy、strncat等"
        },
        "CWE-134": {
            "name": "格式化字符串漏洞",
            "description": "软件使用外部控制的格式化字符串作为printf风格函数的参数",
            "severity": "MEDIUM", 
            "category": "输入验证",
            "detection_patterns": ["printf", "fprintf", "sprintf", "%s", "%x"],
            "mitigation": "使用固定格式字符串，避免用户输入作为格式字符串"
        },
        "CWE-190": {
            "name": "整数溢出或回绕",
            "description": "软件执行整数运算时，结果超出了数据类型可表示的范围",
            "severity": "MEDIUM",
            "category": "数值错误",
            "detection_patterns": ["malloc", "calloc", "realloc", "*", "+"],
            "mitigation": "在分配内存前检查运算结果，使用安全的整数运算库"
        },
        "CWE-416": {
            "name": "释放后使用",
            "description": "程序在释放内存后继续使用该内存区域",
            "severity": "HIGH",
            "category": "内存安全",
            "detection_patterns": ["free", "delete", "使用已释放内存"],
            "mitigation": "释放内存后立即将指针设为NULL，使用智能指针"
        },
        "CWE-476": {
            "name": "空指针解引用",
            "description": "程序解引用一个空指针，导致程序异常终止",
            "severity": "MEDIUM",
            "category": "空指针解引用",
            "detection_patterns": ["NULL", "0x0", "null pointer"],
            "mitigation": "在解引用前检查指针是否为空"
        },
        "CWE-78": {
            "name": "操作系统命令注入",
            "description": "软件构造包含用户控制输入的操作系统命令",
            "severity": "HIGH",
            "category": "注入",
            "detection_patterns": ["system", "exec", "popen", "shell"],
            "mitigation": "避免直接执行shell命令，使用参数化命令或白名单验证"
        },
        "CWE-787": {
            "name": "越界写入",
            "description": "软件写入数据时超出了预期缓冲区的边界",
            "severity": "HIGH",
            "category": "内存安全",
            "detection_patterns": ["buffer overflow", "write overflow"],
            "mitigation": "使用边界检查，启用栈保护机制"
        },
        "CWE-125": {
            "name": "越界读取",
            "description": "软件读取数据时超出了预期缓冲区的边界",
            "severity": "MEDIUM",
            "category": "内存安全",
            "detection_patterns": ["buffer overread", "read overflow"],
            "mitigation": "检查读取边界，使用安全的字符串函数"
        }
    }
    
    @classmethod
    def get_cwe_info(cls, cwe_id: str) -> Dict[str, Any]:
        """获取CWE信息"""
        return cls.cwe_templates.get(cwe_id, {})
    
    @classmethod
    def analyze_cwe_pattern(cls, binary_data: bytes, text_content: str) -> List[Dict[str, Any]]:
        """基于CWE模式分析漏洞"""
        detected_cwes = []
        
        for cwe_id, cwe_info in cls.cwe_templates.items():
            for pattern in cwe_info.get("detection_patterns", []):
                pattern_bytes = pattern.encode()
                if pattern_bytes in binary_data or pattern in text_content:
                    detected_cwes.append({
                        "cwe_id": cwe_id,
                        "pattern": pattern,
                        "info": cwe_info
                    })
        
        return detected_cwes


class VisualizationWindow:
    """可视化窗口 - 支持缩放和拖动"""
    
    def __init__(self, parent, title: str, dot_file: str):
        self.parent = parent
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("1000x700")
        self.window.transient(parent)
        
        self.dot_file = dot_file
        
        # 图像相关变量
        self.original_image = None
        self.current_image = None
        self.photo_image = None
        self.scale_factor = 1.0
        self.min_scale = 0.1
        self.max_scale = 5.0
        
        # 拖动相关变量
        self.drag_start_x = 0
        self.drag_start_y = 0
        self.is_dragging = False
        
        # Canvas相关变量
        self.canvas = None
        self.image_item = None
        
        # 最大化状态
        self.is_maximized = False
        self.normal_geometry = "1000x700"
        
        self._create_widgets()
        
        # 绑定窗口状态变化事件
        self.window.bind('<Configure>', self._on_window_configure)
    
    def _create_widgets(self):
        """创建界面元素"""
        # 主框架
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="📊 可视化图表", font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 工具栏
        toolbar_frame = ttk.Frame(main_frame)
        toolbar_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar_frame, text="保存为PNG", command=self._save_as_png).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar_frame, text="保存为SVG", command=self._save_as_svg).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar_frame, text="查看源码", command=self._view_source).pack(side=tk.LEFT, padx=(0, 5))
        
        # 缩放控制
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(10, 10), fill=tk.Y)
        ttk.Button(toolbar_frame, text="放大 (+)", command=self._zoom_in).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar_frame, text="缩小 (-)", command=self._zoom_out).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar_frame, text="适应窗口", command=self._fit_to_window).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar_frame, text="重置 (100%)", command=self._reset_zoom).pack(side=tk.LEFT, padx=(0, 5))
        
        # 窗口控制按钮
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(10, 10), fill=tk.Y)
        ttk.Button(toolbar_frame, text="最大化", command=self._toggle_maximize).pack(side=tk.LEFT, padx=(0, 5))
        
        # 帮助按钮
        ttk.Separator(toolbar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=(10, 10), fill=tk.Y)
        ttk.Button(toolbar_frame, text="操作说明", command=self._show_help).pack(side=tk.LEFT, padx=(0, 5))
        
        # 状态标签
        self.status_label = ttk.Label(toolbar_frame, text="缩放: 100%")
        self.status_label.pack(side=tk.RIGHT, padx=(10, 0))
        
        # 显示区域
        self.display_frame = ttk.Frame(main_frame)
        self.display_frame.pack(fill=tk.BOTH, expand=True)
        
        # 尝试生成并显示图像
        self._try_display_graph()
    
    def _try_display_graph(self):
        """尝试显示图表"""
        try:
            # 创建临时目录
            temp_dir = "C:/tmp"
            if not os.path.exists(temp_dir):
                temp_dir = tempfile.gettempdir()
            
            # 生成临时PNG用于显示
            temp_png = self._generate_temp_png(temp_dir)
            if temp_png and os.path.exists(temp_png):
                self._display_image(temp_png)
            else:
                self._display_text()
        except Exception as e:
            logger.error(f"显示图表失败: {e}")
            self._display_text()
    
    def _generate_temp_png(self, temp_dir):
        """生成临时PNG用于显示"""
        try:
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            temp_file = os.path.join(temp_dir, f"temp_graph_{int(time.time())}.png")
            
            # 生成中等质量的临时PNG用于显示，并添加中文字体支持
            result = subprocess.run([
                'dot', '-Tpng',
                '-Gdpi=150',        # 中等DPI用于显示
                '-Gsize=15,15!',    # 中等尺寸
                '-Gpad=0.5',
                '-Gbgcolor=white',
                '-Nfontsize=11',
                '-Efontsize=9',
                '-Nfontname=SimHei',  # 使用黑体支持中文
                '-Efontname=SimHei',  # 边标签也使用黑体
                '-Gfontname=SimHei',  # 图标题使用黑体
                self.dot_file, '-o', temp_file
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return temp_file
            else:
                logger.warning(f"生成临时PNG失败: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"生成临时PNG失败: {e}")
            return None
    
    def _save_as_png(self):
        """保存为PNG文件"""
        filename = filedialog.asksaveasfilename(
            title="保存PNG图像",
            defaultextension=".png",
            filetypes=[("PNG图像", "*.png"), ("所有文件", "*.*")]
        )
        
        if filename:
            try:
                # 生成高清PNG文件，添加中文字体支持
                result = subprocess.run([
                    'dot', '-Tpng', 
                    '-Gdpi=300',        # 高DPI用于保存
                    '-Gsize=20,20!',    # 大尺寸
                    '-Gpad=0.5',
                    '-Gbgcolor=white',
                    '-Nfontsize=12',
                    '-Efontsize=10',
                    '-Nfontname=SimHei',  # 使用黑体支持中文
                    '-Efontname=SimHei',  # 边标签也使用黑体
                    '-Gfontname=SimHei',  # 图标题使用黑体
                    self.dot_file, '-o', filename
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    messagebox.showinfo("保存成功", f"高清PNG文件已保存: {filename}")
                else:
                    messagebox.showerror("保存失败", f"无法生成PNG文件: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                messagebox.showerror("保存失败", "生成PNG文件超时")
            except FileNotFoundError:
                messagebox.showerror("保存失败", "未找到Graphviz，请安装Graphviz并确保dot命令在PATH中")
            except Exception as e:
                messagebox.showerror("保存失败", f"保存PNG文件时出错: {e}")
    
    def _save_as_svg(self):
        """保存为SVG文件"""
        filename = filedialog.asksaveasfilename(
            title="保存SVG图像",
            defaultextension=".svg",
            filetypes=[("SVG图像", "*.svg"), ("所有文件", "*.*")]
        )
        
        if filename:
            try:
                # 生成高质量SVG文件，添加中文字体支持
                result = subprocess.run([
                    'dot', '-Tsvg',
                    '-Gpad=0.5',
                    '-Gbgcolor=white',
                    '-Nfontsize=12',
                    '-Efontsize=10',
                    '-Nfontname=SimHei',  # 使用黑体支持中文
                    '-Efontname=SimHei',  # 边标签也使用黑体
                    '-Gfontname=SimHei',  # 图标题使用黑体
                    self.dot_file, '-o', filename
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    messagebox.showinfo("保存成功", f"高质量SVG文件已保存: {filename}")
                else:
                    messagebox.showerror("保存失败", f"无法生成SVG文件: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                messagebox.showerror("保存失败", "生成SVG文件超时")
            except FileNotFoundError:
                messagebox.showerror("保存失败", "未找到Graphviz，请安装Graphviz并确保dot命令在PATH中")
            except Exception as e:
                messagebox.showerror("保存失败", f"保存SVG文件时出错: {e}")
    
    def _view_source(self):
        """查看DOT源码"""
        try:
            with open(self.dot_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 创建源码窗口
            source_window = tk.Toplevel(self.window)
            source_window.title("DOT源码")
            source_window.geometry("600x400")
            
            text_widget = scrolledtext.ScrolledText(source_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert(tk.END, content)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("错误", f"无法读取DOT文件: {e}")
    
    def _display_image(self, image_file: str):
        """显示图像 - 支持缩放和拖动"""
        try:
            # 清除现有内容
            for widget in self.display_frame.winfo_children():
                widget.destroy()
            
            if PIL_AVAILABLE:
                # 加载原始图像
                self.original_image = Image.open(image_file)
                self.current_image = self.original_image.copy()
                
                # 创建可缩放拖动的画布
                self._create_zoomable_canvas()
                
                # 初始显示图像
                self._update_image_display()
                
            else:
                # PIL不可用时显示文本说明
                text_widget = scrolledtext.ScrolledText(self.display_frame, wrap=tk.WORD)
                text_widget.pack(fill=tk.BOTH, expand=True)
                text_widget.insert(tk.END, f"图像文件已生成: {image_file}\n\n请安装PIL库以在界面中查看图像，或使用外部图像查看器打开文件。")
                text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            logger.error(f"显示图像失败: {e}")
            self._display_text()
    
    def _create_zoomable_canvas(self):
        """创建支持缩放和拖动的画布"""
        # 创建画布框架
        canvas_frame = ttk.Frame(self.display_frame)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建画布和滚动条
        self.canvas = tk.Canvas(canvas_frame, bg='white', highlightthickness=0)
        v_scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        h_scrollbar = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        
        self.canvas.configure(
            yscrollcommand=v_scrollbar.set,
            xscrollcommand=h_scrollbar.set
        )
        
        # 打包组件
        self.canvas.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # 配置网格权重
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)
        
        # 绑定鼠标事件
        self._bind_mouse_events()
        
        # 绑定键盘事件
        self.canvas.focus_set()
        self.canvas.bind("<Key>", self._on_key_press)
    
    def _bind_mouse_events(self):
        """绑定鼠标事件"""
        # 鼠标滚轮缩放
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)  # Windows
        self.canvas.bind("<Button-4>", self._on_mouse_wheel)    # Linux
        self.canvas.bind("<Button-5>", self._on_mouse_wheel)    # Linux
        
        # 鼠标左键总是可以拖动
        self.canvas.bind("<Button-1>", self._start_drag)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._end_drag)
        
        # 双击重置（需要过滤掉拖动操作）
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
    
    def _on_mouse_wheel(self, event):
        """处理鼠标滚轮事件进行缩放"""
        if self.original_image is None:
            return
        
        # 获取鼠标位置
        mouse_x = self.canvas.canvasx(event.x)
        mouse_y = self.canvas.canvasy(event.y)
        
        # 计算缩放因子
        if event.delta > 0 or event.num == 4:  # 向上滚动，放大
            zoom_factor = 1.1
        else:  # 向下滚动，缩小
            zoom_factor = 0.9
        
        new_scale = self.scale_factor * zoom_factor
        
        # 限制缩放范围
        if new_scale < self.min_scale:
            new_scale = self.min_scale
        elif new_scale > self.max_scale:
            new_scale = self.max_scale
        
        if new_scale != self.scale_factor:
            # 计算缩放中心
            old_scale = self.scale_factor
            self.scale_factor = new_scale
            
            # 更新图像显示
            self._update_image_display()
            
            # 调整滚动位置以保持鼠标位置不变
            scale_ratio = new_scale / old_scale
            new_x = mouse_x * scale_ratio - event.x
            new_y = mouse_y * scale_ratio - event.y
            
            # 设置新的滚动位置
            self.canvas.xview_moveto(new_x / (self.current_image.width * self.scale_factor))
            self.canvas.yview_moveto(new_y / (self.current_image.height * self.scale_factor))
    
    def _start_drag(self, event):
        """开始拖动"""
        self.drag_start_x = event.x
        self.drag_start_y = event.y
        self.is_dragging = False  # 先设置为False，在移动时才设置为True
        self.drag_threshold = 5   # 拖动阈值，避免误触双击
        
    def _on_drag(self, event):
        """处理拖动"""
        # 计算拖动距离
        dx = event.x - self.drag_start_x
        dy = event.y - self.drag_start_y
        
        # 如果移动距离超过阈值，开始拖动
        if not self.is_dragging and (abs(dx) > self.drag_threshold or abs(dy) > self.drag_threshold):
            self.is_dragging = True
            self.canvas.config(cursor="fleur")
        
        if self.is_dragging:
            # 获取当前滚动位置
            x_view = self.canvas.xview()
            y_view = self.canvas.yview()
            
            # 计算新的滚动位置
            canvas_width = self.canvas.winfo_width()
            canvas_height = self.canvas.winfo_height()
            
            if self.current_image and self.scale_factor > 0:
                img_width = self.current_image.width
                img_height = self.current_image.height
                
                # 更平滑的拖动计算
                if img_width > canvas_width:
                    x_scroll = x_view[0] - dx / (img_width * self.scale_factor)
                    self.canvas.xview_moveto(max(0, min(1, x_scroll)))
                
                if img_height > canvas_height:
                    y_scroll = y_view[0] - dy / (img_height * self.scale_factor)
                    self.canvas.yview_moveto(max(0, min(1, y_scroll)))
            
            self.drag_start_x = event.x
            self.drag_start_y = event.y
    
    def _end_drag(self, event):
        """结束拖动"""
        if self.is_dragging:
            self.is_dragging = False
            self.canvas.config(cursor="")
    
    def _on_double_click(self, event):
        """双击重置缩放"""
        # 只有在没有进行拖动操作时才响应双击
        if not self.is_dragging:
            self._fit_to_window()
    
    def _on_key_press(self, event):
        """处理键盘按键"""
        if event.keysym == "plus" or event.keysym == "equal":
            self._zoom_in()
        elif event.keysym == "minus":
            self._zoom_out()
        elif event.keysym == "0":
            self._reset_zoom()
        elif event.keysym == "f":
            self._fit_to_window()
        elif event.keysym == "F11":
            self._toggle_maximize()
    
    def _update_image_display(self):
        """更新图像显示"""
        if self.original_image is None:
            return
        
        try:
            # 计算缩放后的图像尺寸
            new_width = int(self.original_image.width * self.scale_factor)
            new_height = int(self.original_image.height * self.scale_factor)
            
            # 缩放图像
            if new_width > 0 and new_height > 0:
                self.current_image = self.original_image.resize(
                    (new_width, new_height), 
                    Image.Resampling.LANCZOS
                )
                
                # 转换为PhotoImage
                self.photo_image = ImageTk.PhotoImage(self.current_image)
                
                # 更新画布上的图像
                if self.image_item:
                    self.canvas.delete(self.image_item)
                
                self.image_item = self.canvas.create_image(
                    0, 0, anchor=tk.NW, image=self.photo_image
                )
                
                # 更新滚动区域
                self.canvas.configure(scrollregion=self.canvas.bbox("all"))
                
                # 更新状态标签
                self.status_label.config(text=f"缩放: {int(self.scale_factor * 100)}%")
            
        except Exception as e:
            logger.error(f"更新图像显示失败: {e}")
    
    def _zoom_in(self):
        """放大"""
        new_scale = self.scale_factor * 1.2
        if new_scale <= self.max_scale:
            self.scale_factor = new_scale
            self._update_image_display()
    
    def _zoom_out(self):
        """缩小"""
        new_scale = self.scale_factor / 1.2
        if new_scale >= self.min_scale:
            self.scale_factor = new_scale
            self._update_image_display()
    
    def _reset_zoom(self):
        """重置缩放到100%"""
        self.scale_factor = 1.0
        self._update_image_display()
    
    def _fit_to_window(self):
        """适应窗口大小"""
        if self.original_image is None:
            return
        
        # 获取画布尺寸
        self.canvas.update_idletasks()
        canvas_width = self.canvas.winfo_width()
        canvas_height = self.canvas.winfo_height()
        
        if canvas_width > 1 and canvas_height > 1:
            # 计算适应窗口的缩放因子
            scale_x = canvas_width / self.original_image.width
            scale_y = canvas_height / self.original_image.height
            
            # 选择较小的缩放因子以确保图像完全显示
            fit_scale = min(scale_x, scale_y) * 0.9  # 留一些边距
            
            # 限制缩放范围
            self.scale_factor = max(self.min_scale, min(self.max_scale, fit_scale))
            self._update_image_display()
    
    def _toggle_maximize(self):
        """切换最大化状态"""
        if self.is_maximized:
            # 恢复正常大小
            self.window.state('normal')
            self.window.geometry(self.normal_geometry)
            self.is_maximized = False
            # 更新按钮文本
            self._update_maximize_button_text('最大化')
        else:
            # 保存当前几何形状
            self.normal_geometry = self.window.geometry()
            # 最大化窗口
            try:
                self.window.state('zoomed')  # Windows/Linux
            except tk.TclError:
                # macOS 使用不同的方法
                self.window.attributes('-zoomed', True)
            self.is_maximized = True
            # 更新按钮文本
            self._update_maximize_button_text('还原')
    
    def _update_maximize_button_text(self, text):
        """更新最大化按钮的文本"""
        # 查找并更新最大化按钮的文本
        def find_and_update_button(widget):
            if isinstance(widget, ttk.Button):
                current_text = widget.cget('text')
                if current_text in ['最大化', '还原']:
                    widget.config(text=text)
                    return True
            elif hasattr(widget, 'winfo_children'):
                for child in widget.winfo_children():
                    if find_and_update_button(child):
                        return True
            return False
        
        find_and_update_button(self.window)
    
    def _on_window_configure(self, event):
        """处理窗口配置变化事件"""
        # 只处理窗口本身的配置变化，不处理子组件
        if event.widget == self.window:
            # 检测窗口状态变化
            current_state = self.window.state()
            if current_state == 'zoomed' and not self.is_maximized:
                # 窗口被系统最大化（如双击标题栏）
                self.is_maximized = True
                self._update_maximize_button_text('还原')
            elif current_state == 'normal' and self.is_maximized:
                # 窗口被系统还原
                self.is_maximized = False
                self._update_maximize_button_text('最大化')
    
    def _show_help(self):
        """显示操作说明"""
        help_text = """
🔍 可视化图表操作说明

🖱️ 鼠标操作:
• 滚轮向上: 放大图像
• 滚轮向下: 缩小图像
• 左键拖动: 移动图像查看细节
• 双击: 自动适应窗口大小

⌨️ 键盘快捷键:
• +/= 键: 放大
• - 键: 缩小
• 0 键: 重置到100%
• F 键: 适应窗口
• F11 键: 切换最大化

🔧 工具栏按钮:
• 放大(+): 逐步放大图像
• 缩小(-): 逐步缩小图像
• 适应窗口: 自动调整图像大小适应窗口
• 重置(100%): 恢复原始大小
• 最大化/还原: 切换窗口最大化状态
• 保存为PNG: 创建高清PNG图像文件
• 保存为SVG: 创建矢量SVG图像文件

💡 使用技巧:
• 缩放范围: 10% - 500%
• 高清图像支持300 DPI输出
• 支持拖动查看大图像的不同部分
• 状态栏显示当前缩放比例
        """
        
        messagebox.showinfo("操作说明", help_text)
    
    def _display_text(self):
        """显示文本内容"""
        try:
            # 清除现有内容
            for widget in self.display_frame.winfo_children():
                widget.destroy()
            
            # 读取DOT文件内容
            with open(self.dot_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 创建文本显示区域
            text_widget = scrolledtext.ScrolledText(self.display_frame, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            text_widget.insert(tk.END, f"DOT源码 (安装Graphviz后可查看图形):\n\n{content}")
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            error_text = f"无法读取文件: {e}"
            text_widget = scrolledtext.ScrolledText(self.display_frame, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True)
            text_widget.insert(tk.END, error_text)
            text_widget.config(state=tk.DISABLED)


class ScanProgressDialog:
    """扫描进度对话框"""
    
    def __init__(self, parent):
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("扫描进度")
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)
        
        # 居中显示
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 创建界面
        self._create_widgets()
        
        # 变量
        self.cancelled = False
    
    def _create_widgets(self):
        """创建界面元素"""
        # 主框架
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="正在扫描...", font=("Arial", 12, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 文件名标签
        self.file_label = ttk.Label(main_frame, text="", wraplength=350)
        self.file_label.pack(pady=(0, 10))
        
        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        self.progress.start()
        
        # 状态标签
        self.status_label = ttk.Label(main_frame, text="初始化扫描器...")
        self.status_label.pack(pady=(0, 10))
        
        # 取消按钮
        cancel_button = ttk.Button(main_frame, text="取消", command=self.cancel)
        cancel_button.pack()
    
    def update_file(self, filename: str):
        """更新当前文件"""
        self.file_label.config(text=f"文件: {os.path.basename(filename)}")
    
    def update_status(self, status: str):
        """更新状态"""
        self.status_label.config(text=status)
    
    def cancel(self):
        """取消扫描"""
        self.cancelled = True
        self.dialog.destroy()
    
    def close(self):
        """关闭对话框"""
        self.progress.stop()
        self.dialog.destroy()


class VulnerabilityDetailDialog:
    """漏洞详情对话框"""
    
    def __init__(self, parent, vulnerability: Vulnerability):
        self.parent = parent
        self.vulnerability = vulnerability
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"漏洞详情 - {vulnerability.name}")
        self.dialog.geometry("600x500")
        
        # 居中显示
        self.dialog.transient(parent)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """创建界面元素"""
        # 创建滚动框架
        canvas = tk.Canvas(self.dialog)
        scrollbar = ttk.Scrollbar(self.dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 基本信息
        basic_frame = ttk.LabelFrame(scrollable_frame, text="基本信息", padding="10")
        basic_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 漏洞名称
        ttk.Label(basic_frame, text="漏洞名称:", font=("Arial", 9, "bold")).grid(
            row=0, column=0, sticky="nw", padx=(0, 10)
        )
        ttk.Label(basic_frame, text=self.vulnerability.name, wraplength=400).grid(
            row=0, column=1, sticky="nw"
        )
        
        # 严重性
        ttk.Label(basic_frame, text="严重性:", font=("Arial", 9, "bold")).grid(
            row=1, column=0, sticky="nw", padx=(0, 10), pady=(5, 0)
        )
        severity_frame = ttk.Frame(basic_frame)
        severity_frame.grid(row=1, column=1, sticky="nw", pady=(5, 0))
        
        severity_color = {
            VulnSeverity.CRITICAL: "red",
            VulnSeverity.HIGH: "orange",
            VulnSeverity.MEDIUM: "yellow",
            VulnSeverity.LOW: "green",
            VulnSeverity.INFO: "blue"
        }.get(self.vulnerability.severity, "black")
        
        severity_label = tk.Label(
            severity_frame, 
            text=self.vulnerability.severity.value,
            fg=severity_color,
            font=("Arial", 9, "bold")
        )
        severity_label.pack()
        
        # 描述
        ttk.Label(basic_frame, text="描述:", font=("Arial", 9, "bold")).grid(
            row=2, column=0, sticky="nw", padx=(0, 10), pady=(5, 0)
        )
        ttk.Label(basic_frame, text=self.vulnerability.description, wraplength=400).grid(
            row=2, column=1, sticky="nw", pady=(5, 0)
        )
        
        # 地址信息
        if self.vulnerability.function_address or self.vulnerability.instruction_address:
            addr_frame = ttk.LabelFrame(scrollable_frame, text="地址信息", padding="10")
            addr_frame.pack(fill=tk.X, padx=10, pady=5)
            
            if self.vulnerability.function_address:
                ttk.Label(addr_frame, text="函数地址:", font=("Arial", 9, "bold")).grid(
                    row=0, column=0, sticky="nw", padx=(0, 10)
                )
                ttk.Label(addr_frame, text=f"0x{self.vulnerability.function_address:08x}").grid(
                    row=0, column=1, sticky="nw"
                )
            
            if self.vulnerability.instruction_address:
                ttk.Label(addr_frame, text="指令地址:", font=("Arial", 9, "bold")).grid(
                    row=1, column=0, sticky="nw", padx=(0, 10), pady=(5, 0)
                )
                ttk.Label(addr_frame, text=f"0x{self.vulnerability.instruction_address:08x}").grid(
                    row=1, column=1, sticky="nw", pady=(5, 0)
                )
        
        # 修复建议
        if hasattr(self.vulnerability, 'fix_suggestions') and self.vulnerability.fix_suggestions:
            fix_frame = ttk.LabelFrame(scrollable_frame, text="修复建议", padding="10")
            fix_frame.pack(fill=tk.X, padx=10, pady=5)
            
            for i, fix in enumerate(self.vulnerability.fix_suggestions):
                if hasattr(fix, 'description'):
                    description = fix.description
                else:
                    description = str(fix)
                ttk.Label(fix_frame, text=f"{i+1}. {description}", wraplength=500).pack(
                    anchor="w", pady=(0, 5)
                )
        
        # 汇编指令信息
        if self.vulnerability.function_address or self.vulnerability.instruction_address:
            asm_frame = ttk.LabelFrame(scrollable_frame, text="汇编代码分析", padding="10")
            asm_frame.pack(fill=tk.X, padx=10, pady=5)
            
            # 创建Notebook用于显示不同格式的代码
            asm_notebook = ttk.Notebook(asm_frame)
            asm_notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
            
            # 十六进制视图
            hex_frame = ttk.Frame(asm_notebook)
            asm_notebook.add(hex_frame, text="十六进制")
            
            hex_text = scrolledtext.ScrolledText(hex_frame, height=8, wrap=tk.NONE, font=("Courier", 9))
            hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # 反汇编视图
            disasm_frame = ttk.Frame(asm_notebook)
            asm_notebook.add(disasm_frame, text="反汇编")
            
            disasm_text = scrolledtext.ScrolledText(disasm_frame, height=8, wrap=tk.NONE, font=("Courier", 9))
            disasm_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # 伪代码视图
            pseudo_frame = ttk.Frame(asm_notebook)
            asm_notebook.add(pseudo_frame, text="伪代码")
            
            pseudo_text = scrolledtext.ScrolledText(pseudo_frame, height=8, wrap=tk.WORD, font=("Courier", 9))
            pseudo_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            # 填充内容
            self._populate_assembly_views(hex_text, disasm_text, pseudo_text)
        
        # CWE信息
        if hasattr(self.vulnerability, 'category') and self.vulnerability.category and self.vulnerability.category.cwe_id:
            cwe_frame = ttk.LabelFrame(scrollable_frame, text="CWE信息", padding="10")
            cwe_frame.pack(fill=tk.X, padx=10, pady=5)
            
            cwe_info = CWEDatabase.get_cwe_info(self.vulnerability.category.cwe_id)
            if cwe_info:
                ttk.Label(cwe_frame, text=f"CWE编号: {self.vulnerability.category.cwe_id}", font=("Arial", 9, "bold")).pack(anchor="w")
                ttk.Label(cwe_frame, text=f"分类: {cwe_info.get('category', 'Unknown')}", wraplength=500).pack(anchor="w", pady=(2, 0))
                ttk.Label(cwe_frame, text=f"缓解措施: {cwe_info.get('mitigation', 'No specific mitigation available')}", wraplength=500).pack(anchor="w", pady=(2, 0))
        
        # 详细信息
        if self.vulnerability.details:
            details_frame = ttk.LabelFrame(scrollable_frame, text="详细信息", padding="10")
            details_frame.pack(fill=tk.X, padx=10, pady=5)
            
            ttk.Label(details_frame, text=self.vulnerability.details, wraplength=500).pack(
                anchor="w"
            )
        
        # 打包滚动组件
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 关闭按钮
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="关闭", command=self.dialog.destroy).pack(
            side="right"
        )
    
    def _populate_assembly_views(self, hex_text, disasm_text, pseudo_text):
        """填充汇编代码视图"""
        try:
            # 获取地址信息
            address = self.vulnerability.function_address or self.vulnerability.instruction_address
            if not address:
                address = 0x40000000  # 默认地址
            
            # 生成示例十六进制数据
            hex_content = self._generate_hex_view(address)
            hex_text.insert(tk.END, hex_content)
            hex_text.config(state=tk.DISABLED)
            
            # 生成示例反汇编代码
            disasm_content = self._generate_disassembly_view(address)
            disasm_text.insert(tk.END, disasm_content)
            disasm_text.config(state=tk.DISABLED)
            
            # 生成示例伪代码
            pseudo_content = self._generate_pseudo_code(address)
            pseudo_text.insert(tk.END, pseudo_content)
            pseudo_text.config(state=tk.DISABLED)
            
        except Exception as e:
            error_msg = f"无法生成汇编代码视图: {e}"
            for text_widget in [hex_text, disasm_text, pseudo_text]:
                text_widget.insert(tk.END, error_msg)
                text_widget.config(state=tk.DISABLED)
    
    def _generate_hex_view(self, address: int) -> str:
        """生成十六进制视图"""
        hex_content = f"地址范围: 0x{address:08x} - 0x{address+64:08x}\n\n"
        
        # 模拟十六进制数据
        sample_data = [
            "55 48 89 e5 48 83 ec 20",  # push rbp; mov rbp, rsp; sub rsp, 0x20
            "48 89 7d f8 48 89 75 f0",  # mov [rbp-8], rdi; mov [rbp-16], rsi
            "48 8b 45 f8 48 8b 55 f0",  # mov rax, [rbp-8]; mov rdx, [rbp-16]
            "48 01 d0 48 89 45 e8 48",  # add rax, rdx; mov [rbp-24], rax
            "8b 45 e8 c9 c3 90 90 90",  # mov eax, [rbp-24]; leave; ret; nop; nop; nop
        ]
        
        for i, data in enumerate(sample_data):
            addr = address + (i * 8)
            hex_content += f"0x{addr:08x}: {data}\n"
        
        return hex_content
    
    def _generate_disassembly_view(self, address: int) -> str:
        """生成反汇编视图"""
        disasm_content = f"函数反汇编 (地址: 0x{address:08x})\n\n"
        
        # 根据漏洞类型生成相应的汇编代码
        vuln_name = self.vulnerability.name.lower()
        
        if "危险函数" in self.vulnerability.name or "strcpy" in vuln_name:
            disasm_content += """0x40001000: push   rbp
0x40001001: mov    rbp, rsp
0x40001004: sub    rsp, 0x20
0x40001008: mov    QWORD PTR [rbp-0x18], rdi    ; dest parameter
0x4000100c: mov    QWORD PTR [rbp-0x20], rsi    ; src parameter
0x40001010: mov    rax, QWORD PTR [rbp-0x20]    ; load src
0x40001014: mov    rdi, QWORD PTR [rbp-0x18]    ; load dest
0x40001018: mov    rsi, rax                     ; set src as second arg
0x4000101b: call   0x401030 <strcpy@plt>        ; 危险函数调用!
0x40001020: mov    rax, QWORD PTR [rbp-0x18]    ; return dest
0x40001024: leave
0x40001025: ret"""
        
        elif "格式化字符串" in self.vulnerability.name or "printf" in vuln_name:
            disasm_content += """0x40001000: push   rbp
0x40001001: mov    rbp, rsp
0x40001004: sub    rsp, 0x10
0x40001008: mov    QWORD PTR [rbp-0x8], rdi     ; format string
0x4000100c: mov    rax, QWORD PTR [rbp-0x8]     ; load format
0x40001010: mov    rdi, rax                     ; 用户输入直接作为格式字符串!
0x40001013: mov    eax, 0x0
0x40001018: call   0x401020 <printf@plt>        ; 格式化字符串漏洞!
0x4000101d: nop
0x4000101e: leave
0x4000101f: ret"""
        
        elif "nop" in vuln_name.lower():
            disasm_content += """0x40001000: nop                              ; NOP滑行开始
0x40001001: nop
0x40001002: nop
0x40001003: nop                              ; 大量NOP指令
0x40001004: nop
0x40001005: nop
0x40001006: nop
0x40001007: nop                              ; 可能被用于滑行攻击
0x40001008: mov    eax, 0xdeadbeef           ; shellcode入口点
0x4000100d: call   rax                       ; 执行恶意代码"""
        
        else:
            disasm_content += """0x40001000: push   rbp
0x40001001: mov    rbp, rsp
0x40001004: sub    rsp, 0x10
0x40001008: mov    DWORD PTR [rbp-0x4], edi
0x4000100b: mov    QWORD PTR [rbp-0x10], rsi
0x4000100f: mov    eax, DWORD PTR [rbp-0x4]
0x40001012: leave
0x40001013: ret"""
        
        return disasm_content
    
    def _generate_pseudo_code(self, address: int) -> str:
        """生成伪代码视图"""
        pseudo_content = f"函数伪代码 (地址: 0x{address:08x})\n\n"
        
        vuln_name = self.vulnerability.name.lower()
        
        if "危险函数" in self.vulnerability.name or "strcpy" in vuln_name:
            pseudo_content += """void vulnerable_function(char* dest, char* src) {
    // 危险: 未检查dest缓冲区大小
    strcpy(dest, src);  // ← 缓冲区溢出风险
    return dest;
}

// 建议修复:
void safe_function(char* dest, size_t dest_size, char* src) {
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\\0';  // 确保字符串终止
}"""
        
        elif "格式化字符串" in self.vulnerability.name or "printf" in vuln_name:
            pseudo_content += """void vulnerable_function(char* user_input) {
    // 危险: 用户输入直接作为格式字符串
    printf(user_input);  // ← 格式化字符串漏洞
}

// 建议修复:
void safe_function(char* user_input) {
    printf("%s", user_input);  // 使用固定格式字符串
}"""
        
        elif "nop" in vuln_name.lower():
            pseudo_content += """// NOP滑行攻击模式:
// 攻击者可能注入大量NOP指令来增加命中概率

unsigned char exploit_buffer[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP滑行
    0x90, 0x90, 0x90, 0x90,  // NOP滑行  
    0x90, 0x90, 0x90, 0x90,  // NOP滑行
    // ... 更多NOP指令 ...
    0xcc, 0xcc, 0xcc, 0xcc   // shellcode开始
};

// 防护措施:
// 1. 启用NX位保护
// 2. 启用ASLR
// 3. 栈金丝雀保护"""
        
        elif "栈金丝雀" in self.vulnerability.name or "stack" in vuln_name:
            pseudo_content += """void vulnerable_function() {
    char buffer[256];
    
    // 缺少栈保护机制
    gets(buffer);  // 无边界检查的输入
    
    // 攻击者可以覆盖返回地址
    // 建议: 编译时添加 -fstack-protector-all
}"""
        
        elif "nx" in vuln_name.lower() or "dep" in vuln_name.lower():
            pseudo_content += """// NX位(No-Execute)保护缺失
// 
// 问题: 栈或堆上的数据可能被执行为代码
// 影响: 攻击者可以执行注入的shellcode
//
// 修复措施:
// 1. 编译时启用NX位支持
// 2. 操作系统层面启用DEP
// 3. 确保GNU_STACK段正确标记
//
// Linux编译示例:
// gcc -Wl,-z,noexecstack program.c"""
        
        elif "pie" in vuln_name.lower() or "aslr" in vuln_name.lower():
            pseudo_content += """// PIE/ASLR保护缺失
//
// 问题: 程序加载地址固定，便于攻击者预测
// 影响: ROP/JOP攻击更容易实现
//
// 修复措施:
// 1. 编译为位置无关可执行文件
// 2. 启用系统ASLR
//
// 编译示例:
// gcc -fPIE -pie program.c
//
// 检查方法:
// readelf -h program | grep Type
// 应显示: DYN (Shared object file)"""
        
        else:
            pseudo_content += """// 通用安全建议:
//
// 1. 输入验证:
//    - 检查所有用户输入
//    - 验证数据长度和格式
//
// 2. 边界检查:
//    - 使用安全的字符串函数
//    - 避免缓冲区溢出
//
// 3. 编译保护:
//    - 启用栈保护 (-fstack-protector)
//    - 启用PIE (-fPIE -pie)
//    - 启用FORTIFY_SOURCE (-D_FORTIFY_SOURCE=2)
//
// 4. 运行时保护:
//    - 启用ASLR
//    - 启用NX位/DEP"""
        
        return pseudo_content


def get_temp_directory():
    """获取临时文件目录"""
    temp_dir = "C:/tmp"
    if not os.path.exists(temp_dir):
        temp_dir = tempfile.gettempdir()
        
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    return temp_dir


def cleanup_temp_files():
    """清理临时.dot文件"""
    try:
        temp_dir = "C:/tmp" if os.path.exists("C:/tmp") else tempfile.gettempdir()
        
        # 清理当前会话生成的DOT文件
        if os.path.exists(temp_dir):
            for file in os.listdir(temp_dir):
                if file.endswith('.dot') and ('call_graph_' in file or 'cfg_' in file):
                    try:
                        file_path = os.path.join(temp_dir, file)
                        # 只删除1小时内创建的文件，避免删除其他程序的文件
                        if time.time() - os.path.getctime(file_path) < 3600:
                            os.remove(file_path)
                            logger.info(f"清理临时文件: {file}")
                    except Exception as e:
                        logger.warning(f"清理文件失败 {file}: {e}")
    except Exception as e:
        logger.warning(f"清理临时文件失败: {e}")


class BinaryVulnScannerGUI:
    """图形界面主类"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("二进制漏洞扫描器")
        self.root.geometry("900x700")
        
        # 变量
        self.scanner = None
        self.current_vulnerabilities = []
        self.current_functions = []
        self.current_binary_data = None
        self.current_metadata = {}
        self.scan_queue = queue.Queue()
        
        # 创建界面
        self._create_widgets()
        self._create_menu()
        
        # 启动消息处理
        self._process_queue()
    
    def _create_menu(self):
        """创建菜单"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开文件", command=self.browse_file)
        file_menu.add_command(label="打开目录", command=self.browse_directory)
        file_menu.add_separator()
        file_menu.add_command(label="导出报告", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._safe_quit)
        
        # 工具菜单
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="工具", menu=tools_menu)
        tools_menu.add_command(label="清除结果", command=self.clear_results)
        tools_menu.add_command(label="扫描选项", command=self.show_options)
        
        # 可视化菜单
        viz_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="可视化", menu=viz_menu)
        viz_menu.add_command(label="查看调用图", command=self.view_call_graph)
        viz_menu.add_command(label="查看控制流图", command=self.view_control_flow_graph)
        viz_menu.add_command(label="CWE分析报告", command=self.show_cwe_analysis)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)
    
    def _create_widgets(self):
        """创建界面元素"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(
            main_frame, 
            text="🔍 二进制漏洞扫描器", 
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 10))
        
        # 文件选择框架
        file_frame = ttk.LabelFrame(main_frame, text="目标选择", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 文件路径
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(path_frame, text="路径:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(path_frame, textvariable=self.path_var, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=(5, 5), fill=tk.X, expand=True)
        
        # 浏览按钮
        button_frame = ttk.Frame(path_frame)
        button_frame.pack(side=tk.RIGHT)
        
        ttk.Button(button_frame, text="浏览文件", command=self.browse_file).pack(
            side=tk.LEFT, padx=(0, 5)
        )
        ttk.Button(button_frame, text="浏览目录", command=self.browse_directory).pack(
            side=tk.LEFT
        )
        
        # 扫描选项
        options_frame = ttk.Frame(file_frame)
        options_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.batch_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="批量扫描", variable=self.batch_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        
        self.symbolic_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="符号执行", variable=self.symbolic_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        
        self.dataflow_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="数据流分析", variable=self.dataflow_var).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        
        # 扫描按钮
        scan_button = ttk.Button(
            file_frame, 
            text="🔍 开始扫描", 
            command=self.start_scan,
            style="Accent.TButton"
        )
        scan_button.pack(pady=(10, 0))
        
        # 结果显示区域
        results_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # 创建Treeview
        columns = ("序号", "漏洞名称", "严重性", "类型", "函数地址")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        # 设置列
        self.tree.heading("序号", text="序号")
        self.tree.heading("漏洞名称", text="漏洞名称")
        self.tree.heading("严重性", text="严重性")
        self.tree.heading("类型", text="类型")
        self.tree.heading("函数地址", text="函数地址")
        
        self.tree.column("序号", width=50, anchor="center")
        self.tree.column("漏洞名称", width=300)
        self.tree.column("严重性", width=80, anchor="center")
        self.tree.column("类型", width=150)
        self.tree.column("函数地址", width=120, anchor="center")
        
        # 绑定双击事件
        self.tree.bind("<Double-1>", self.show_vulnerability_detail)
        
        # 滚动条
        scrollbar_v = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_h = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
        
        # 打包组件
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_v.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_h.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 状态栏
        self.status_bar = ttk.Label(
            main_frame, 
            text="就绪", 
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
    
    def browse_file(self):
        """浏览文件"""
        filename = filedialog.askopenfilename(
            title="选择二进制文件",
            filetypes=[
                ("所有文件", "*.*"),
                ("可执行文件", "*.exe"),
                ("动态库", "*.dll"),
                ("共享库", "*.so"),
                ("Mach-O文件", "*.dylib")
            ]
        )
        if filename:
            self.path_var.set(filename)
            self.batch_var.set(False)
    
    def browse_directory(self):
        """浏览目录"""
        directory = filedialog.askdirectory(title="选择目录")
        if directory:
            self.path_var.set(directory)
            self.batch_var.set(True)
    
    def start_scan(self):
        """开始扫描"""
        path = self.path_var.get().strip()
        if not path:
            messagebox.showerror("错误", "请选择要扫描的文件或目录")
            return
        
        if not os.path.exists(path):
            messagebox.showerror("错误", "选择的路径不存在")
            return
        
        # 清除之前的结果
        self.clear_results()
        
        # 创建进度对话框
        progress_dialog = ScanProgressDialog(self.root)
        
        # 启动扫描线程
        scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(path, progress_dialog),
            daemon=True
        )
        scan_thread.start()
    
    def _scan_worker(self, path: str, progress_dialog: ScanProgressDialog):
        """扫描工作线程"""
        try:
            # 初始化扫描器
            progress_dialog.update_status("初始化扫描器...")
            
            if SCANNER_TYPE == "enterprise":
                self.scanner = EnterpriseBinaryVulnScanner()
                # 扫描选项
                options = {
                    "enable_symbolic": self.symbolic_var.get(),
                    "enable_dataflow": self.dataflow_var.get(),
                    "enable_plugins": True,
                    "max_workers": 2
                }
                
                if self.batch_var.get() or os.path.isdir(path):
                    # 批量扫描
                    progress_dialog.update_status("扫描目录...")
                    progress_dialog.update_file(path)
                    
                    results = self.scanner.scan_directory(path, **options)
                    
                    all_vulnerabilities = []
                    for file_path, (vulnerabilities, metadata) in results.items():
                        if not progress_dialog.cancelled:
                            all_vulnerabilities.extend(vulnerabilities)
                    
                    if not progress_dialog.cancelled:
                        self.scan_queue.put(("batch_complete", all_vulnerabilities))
                else:
                    # 单文件扫描
                    progress_dialog.update_status("分析文件...")
                    progress_dialog.update_file(path)
                    
                    vulnerabilities, metadata = self.scanner.scan_file(path, **options)
                    
                    # 获取函数信息用于可视化
                    binary_data = self.scanner._load_binary(path)
                    format_type, arch = self.scanner._detect_file_info(binary_data)
                    functions = self.scanner._perform_disassembly_analysis(binary_data, format_type, arch)
                    
                    # 更新metadata中的格式和架构信息
                    metadata["format"] = format_type.value
                    metadata["architecture"] = arch.value
                    
                    if not progress_dialog.cancelled:
                        self.scan_queue.put(("scan_complete", (vulnerabilities, functions, binary_data, metadata)))
            
            elif SCANNER_TYPE == "advanced":
                self.scanner = EnterpriseBinaryVulnScanner(path)
                
                progress_dialog.update_status("分析文件...")
                progress_dialog.update_file(path)
                
                vulnerabilities = self.scanner.scan()
                
                if not progress_dialog.cancelled:
                    # 为兼容性，提供空的函数列表和二进制数据
                    try:
                        with open(path, 'rb') as f:
                            binary_data = f.read()
                        
                        # 创建基础元数据
                        metadata = {
                            "file_path": path,
                            "file_size": len(binary_data),
                            "format": "Unknown",
                            "architecture": "Unknown",
                            "scanner_type": SCANNER_TYPE
                        }
                        
                        # 尝试检测文件格式和架构
                        if hasattr(self.scanner, '_detect_file_info'):
                            try:
                                format_type, arch = self.scanner._detect_file_info(binary_data)
                                metadata["format"] = format_type.value
                                metadata["architecture"] = arch.value
                            except:
                                pass
                                
                    except:
                        binary_data = b''
                        metadata = {
                            "file_path": path,
                            "format": "Unknown",
                            "architecture": "Unknown",
                            "scanner_type": SCANNER_TYPE
                        }
                    self.scan_queue.put(("scan_complete", (vulnerabilities, [], binary_data, metadata)))
            
            else:  # basic scanner
                self.scanner = EnterpriseBinaryVulnScanner(path)
                
                progress_dialog.update_status("分析文件...")
                progress_dialog.update_file(path)
                
                vulnerabilities = self.scanner.scan()
                
                if not progress_dialog.cancelled:
                    # 为兼容性，提供空的函数列表和二进制数据
                    try:
                        with open(path, 'rb') as f:
                            binary_data = f.read()
                        
                        # 创建基础元数据
                        metadata = {
                            "file_path": path,
                            "file_size": len(binary_data),
                            "format": "Unknown",
                            "architecture": "Unknown",
                            "scanner_type": SCANNER_TYPE
                        }
                        
                        # 尝试检测文件格式和架构
                        if hasattr(self.scanner, '_detect_file_info'):
                            try:
                                format_type, arch = self.scanner._detect_file_info(binary_data)
                                metadata["format"] = format_type.value
                                metadata["architecture"] = arch.value
                            except:
                                pass
                                
                    except:
                        binary_data = b''
                        metadata = {
                            "file_path": path,
                            "format": "Unknown",
                            "architecture": "Unknown",
                            "scanner_type": SCANNER_TYPE
                        }
                    self.scan_queue.put(("scan_complete", (vulnerabilities, [], binary_data, metadata)))
        
        except Exception as e:
            if not progress_dialog.cancelled:
                self.scan_queue.put(("error", str(e)))
        
        finally:
            if not progress_dialog.cancelled:
                self.scan_queue.put(("close_progress", progress_dialog))
    
    def _process_queue(self):
        """处理队列消息"""
        try:
            while True:
                message_type, data = self.scan_queue.get_nowait()
                
                if message_type == "scan_complete":
                    self._handle_scan_complete(data)
                elif message_type == "batch_complete":
                    self._handle_batch_complete(data)
                elif message_type == "error":
                    self._handle_scan_error(data)
                elif message_type == "close_progress":
                    data.close()
        
        except queue.Empty:
            pass
        
        # 继续处理
        self.root.after(100, self._process_queue)
    
    def _handle_scan_complete(self, data):
        """处理扫描完成"""
        if isinstance(data, tuple) and len(data) >= 4:
            vulnerabilities, functions, binary_data, metadata = data
            self.current_functions = functions
            self.current_binary_data = binary_data
            self.current_metadata = metadata
        elif isinstance(data, tuple) and len(data) >= 3:
            vulnerabilities, functions, binary_data = data
            self.current_functions = functions
            self.current_binary_data = binary_data
            self.current_metadata = {}
        elif isinstance(data, tuple) and len(data) == 2:
            vulnerabilities, functions = data
            self.current_functions = functions
            self.current_binary_data = None
            self.current_metadata = {}
        else:
            vulnerabilities = data
            self.current_functions = []
            self.current_binary_data = None
            self.current_metadata = {}
            
        self.current_vulnerabilities = vulnerabilities
        self._update_results_display()
        
        self.status_bar.config(text=f"扫描完成 - 发现 {len(vulnerabilities)} 个漏洞")
        
        if vulnerabilities:
            messagebox.showinfo(
                "扫描完成",
                f"扫描完成！\n发现 {len(vulnerabilities)} 个潜在漏洞。\n\n"
                "双击漏洞项目查看详细信息。"
            )
        else:
            messagebox.showinfo("扫描完成", "扫描完成！未发现漏洞。")
    
    def _handle_batch_complete(self, vulnerabilities: List[Vulnerability]):
        """处理批量扫描完成"""
        self._handle_scan_complete(vulnerabilities)
    
    def _handle_scan_error(self, error_message: str):
        """处理扫描错误"""
        self.status_bar.config(text=f"扫描失败: {error_message}")
        messagebox.showerror("扫描错误", f"扫描过程中发生错误:\n{error_message}")
    
    def _update_results_display(self):
        """更新结果显示"""
        # 清除现有项目
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 添加新结果
        for i, vuln in enumerate(self.current_vulnerabilities, 1):
            # 获取漏洞类型
            vuln_type = ""
            if hasattr(vuln, 'category') and vuln.category:
                vuln_type = vuln.category.name
            
            # 获取函数地址
            func_addr = ""
            if vuln.function_address:
                func_addr = f"0x{vuln.function_address:08x}"
            
            # 插入项目
            item = self.tree.insert("", "end", values=(
                i,
                vuln.name,
                vuln.severity.value,
                vuln_type,
                func_addr
            ))
            
            # 设置颜色标记
            if vuln.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
                self.tree.set(item, "严重性", "🔴 " + vuln.severity.value)
            elif vuln.severity == VulnSeverity.MEDIUM:
                self.tree.set(item, "严重性", "🟡 " + vuln.severity.value)
            else:
                self.tree.set(item, "严重性", "🟢 " + vuln.severity.value)
    
    def show_vulnerability_detail(self, event):
        """显示漏洞详情"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.tree.item(item, "values")
        index = int(values[0]) - 1
        
        if 0 <= index < len(self.current_vulnerabilities):
            vulnerability = self.current_vulnerabilities[index]
            VulnerabilityDetailDialog(self.root, vulnerability)
    
    def clear_results(self):
        """清除结果"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.current_vulnerabilities = []
        self.status_bar.config(text="就绪")
    
    def export_report(self):
        """导出报告"""
        if not self.current_vulnerabilities:
            messagebox.showwarning("警告", "没有可导出的扫描结果")
            return
        
        # 选择保存位置
        filename = filedialog.asksaveasfilename(
            title="导出报告",
            defaultextension=".json",
            filetypes=[
                ("JSON报告", "*.json"),
                ("HTML报告", "*.html"),
                ("XML报告", "*.xml")
            ]
        )
        
        if filename:
            try:
                # 根据文件扩展名确定格式
                ext = os.path.splitext(filename)[1].lower()
                format_map = {".json": "json", ".html": "html", ".xml": "xml"}
                format_type = format_map.get(ext, "json")
                
                # 生成报告
                if SCANNER_TYPE == "enterprise" and self.scanner and hasattr(self.scanner, 'generate_reports'):
                    # 合并当前元数据和导出时间
                    metadata = {
                        "target": self.path_var.get(),
                        "export_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                        **self.current_metadata  # 包含文件格式和架构信息
                    }
                    
                    report_files = self.scanner.generate_reports(
                        self.current_vulnerabilities,
                        self.path_var.get(),
                        metadata,
                        [format_type]
                    )
                    
                    if report_files:
                        # 重命名到指定位置
                        import shutil
                        shutil.move(report_files[0], filename)
                        messagebox.showinfo("成功", f"报告已导出到: {filename}")
                    else:
                        messagebox.showerror("错误", "报告生成失败")
                else:
                    # 简单导出JSON格式
                    self._export_simple_json(filename)
                    messagebox.showinfo("成功", f"报告已导出到: {filename}")
            
            except Exception as e:
                messagebox.showerror("错误", f"导出报告失败: {e}")
    
    def _export_simple_json(self, filename: str):
        """简单JSON导出"""
        import json
        
        # 构建包含完整元数据的扫描信息
        scan_info = {
            "target": self.path_var.get(),
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_type": SCANNER_TYPE,
            "total_vulnerabilities": len(self.current_vulnerabilities),
            "format": self.current_metadata.get('format', 'Unknown'),
            "architecture": self.current_metadata.get('architecture', 'Unknown'),
            "file_size": self.current_metadata.get('file_size', 0),
            "file_hash": self.current_metadata.get('file_hash', '')
        }
        
        report_data = {
            "scan_info": scan_info,
            "vulnerabilities": []
        }
        
        for vuln in self.current_vulnerabilities:
            vuln_data = {
                "name": vuln.name,
                "severity": vuln.severity.value,
                "description": vuln.description
            }
            
            if hasattr(vuln, 'function_address') and vuln.function_address:
                vuln_data["function_address"] = f"0x{vuln.function_address:08x}"
            
            if hasattr(vuln, 'instruction_address') and vuln.instruction_address:
                vuln_data["instruction_address"] = f"0x{vuln.instruction_address:08x}"
            
            if hasattr(vuln, 'details') and vuln.details:
                vuln_data["details"] = vuln.details
            
            report_data["vulnerabilities"].append(vuln_data)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def show_options(self):
        """显示扫描选项"""
        options_dialog = tk.Toplevel(self.root)
        options_dialog.title("扫描选项")
        options_dialog.geometry("300x200")
        options_dialog.resizable(False, False)
        options_dialog.transient(self.root)
        
        # 选项框架
        options_frame = ttk.Frame(options_dialog, padding="20")
        options_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(options_frame, text="高级扫描选项:", font=("Arial", 12, "bold")).pack(
            anchor="w", pady=(0, 10)
        )
        
        ttk.Checkbutton(
            options_frame, 
            text="启用符号执行分析", 
            variable=self.symbolic_var
        ).pack(anchor="w", pady=(0, 5))
        
        ttk.Checkbutton(
            options_frame, 
            text="启用数据流分析", 
            variable=self.dataflow_var
        ).pack(anchor="w", pady=(0, 5))
        
        # 关闭按钮
        ttk.Button(options_frame, text="确定", command=options_dialog.destroy).pack(
            pady=(20, 0)
        )
    
    def show_about(self):
        """显示关于对话框"""
        about_text = """
二进制漏洞扫描器 v1.0.0

一个用于检测二进制可执行文件安全漏洞的工具

主要功能:
• 支持多种文件格式 (ELF, PE, Mach-O)
• 多架构支持 (X86, X64, ARM, MIPS)
• 污点分析和数据流分析
• 符号执行技术
• 可视化分析结果
• 批量扫描功能

作者: 开发团队
版权所有 © 2024
        """
        
        messagebox.showinfo("关于", about_text)
    
    def view_call_graph(self):
        """查看调用图"""
        if not self.current_functions:
            messagebox.showwarning("警告", "没有可用的函数信息，请先扫描文件")
            return
        
        try:
            # 使用扫描器的可视化生成器
            if SCANNER_TYPE == "enterprise" and self.scanner:
                viz_files = self.scanner.generate_visualizations(self.current_functions)
                
                # 查找调用图文件
                call_graph_file = None
                for file in viz_files:
                    if "call_graph" in file:
                        call_graph_file = file
                        break
                
                if call_graph_file and os.path.exists(call_graph_file):
                    # 显示可视化窗口
                    VisualizationWindow(self.root, "函数调用图", call_graph_file)
                else:
                    messagebox.showerror("错误", "无法生成调用图文件")
            else:
                # 简化的调用图生成
                self._generate_simple_call_graph()
                
        except Exception as e:
            messagebox.showerror("错误", f"生成调用图失败: {e}")
    
    def _generate_simple_call_graph(self):
        """生成简化的调用图"""
        try:
            dot_content = "digraph CallGraph {\n"
            dot_content += "    rankdir=TB;\n"
            dot_content += "    node [shape=box, style=filled, fillcolor=lightblue];\n"
            dot_content += "    edge [color=blue];\n"
            
            # 添加函数节点和调用关系
            for func in self.current_functions[:10]:  # 限制数量
                func_name = func.name if hasattr(func, 'name') else f"func_{id(func)}"
                dot_content += f'    "{func_name}" [label="{func_name}"];\n'
                
                if hasattr(func, 'calls'):
                    for call in func.calls[:5]:  # 限制调用数量
                        dot_content += f'    "{func_name}" -> "{call}";\n'
            
            dot_content += "}\n"
            
            # 使用临时目录保存DOT文件
            temp_dir = get_temp_directory()
            dot_file = os.path.join(temp_dir, f"call_graph_{int(time.time())}.dot")
            with open(dot_file, 'w', encoding='utf-8') as f:
                f.write(dot_content)
            
            # 显示可视化窗口
            VisualizationWindow(self.root, "函数调用图", dot_file)
            
        except Exception as e:
            messagebox.showerror("错误", f"生成简化调用图失败: {e}")
    
    def view_control_flow_graph(self):
        """查看控制流图"""
        if not self.current_functions:
            messagebox.showwarning("警告", "没有可用的函数信息，请先扫描文件")
            return
        
        # 函数选择对话框
        selected_func = self._show_function_selection_dialog()
        if not selected_func:
            return
        
        try:
            # 使用扫描器的可视化生成器
            if SCANNER_TYPE == "enterprise" and self.scanner:
                cfg_file = self.scanner.visualization_generator.generate_control_flow_graph(selected_func)
                
                if cfg_file and os.path.exists(cfg_file):
                    # 显示可视化窗口
                    func_name = selected_func.name if hasattr(selected_func, 'name') else "function"
                    VisualizationWindow(self.root, f"控制流图 - {func_name}", cfg_file)
                else:
                    messagebox.showerror("错误", "无法生成控制流图文件")
            else:
                # 简化的控制流图生成
                self._generate_simple_control_flow_graph(selected_func)
                
        except Exception as e:
            messagebox.showerror("错误", f"生成控制流图失败: {e}")
    
    def _show_function_selection_dialog(self):
        """显示函数选择对话框"""
        if len(self.current_functions) == 1:
            return self.current_functions[0]
        
        # 创建函数选择对话框
        selection_dialog = tk.Toplevel(self.root)
        selection_dialog.title("选择函数")
        selection_dialog.geometry("500x400")
        selection_dialog.transient(self.root)
        selection_dialog.grab_set()
        
        # 居中显示
        selection_dialog.update_idletasks()
        x = (selection_dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (selection_dialog.winfo_screenheight() // 2) - (400 // 2)
        selection_dialog.geometry(f"500x400+{x}+{y}")
        
        selected_function = None
        
        # 主框架
        main_frame = ttk.Frame(selection_dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="🔍 选择要分析的函数", font=("Arial", 12, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 函数列表框架
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 创建Treeview显示函数列表
        columns = ("函数名", "地址", "大小", "调用数")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)
        
        # 设置列标题
        tree.heading("函数名", text="函数名")
        tree.heading("地址", text="地址")
        tree.heading("大小", text="大小")
        tree.heading("调用数", text="调用数")
        
        # 设置列宽
        tree.column("函数名", width=200)
        tree.column("地址", width=100, anchor="center")
        tree.column("大小", width=80, anchor="center")
        tree.column("调用数", width=80, anchor="center")
        
        # 添加滚动条
        scrollbar_v = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar_v.set)
        
        # 填充函数信息
        for i, func in enumerate(self.current_functions[:20]):  # 限制显示前20个函数
            func_name = func.name if hasattr(func, 'name') else f"func_{i}"
            address = f"0x{func.address:08x}" if hasattr(func, 'address') else "Unknown"
            size = str(func.size) if hasattr(func, 'size') and func.size > 0 else "Unknown"
            call_count = str(len(func.calls)) if hasattr(func, 'calls') else "0"
            
            tree.insert("", "end", values=(func_name, address, size, call_count))
        
        # 打包组件
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_v.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        def on_select():
            nonlocal selected_function
            selection = tree.selection()
            if selection:
                item = selection[0]
                values = tree.item(item, "values")
                func_name = values[0]
                
                # 根据函数名找到对应的函数对象
                for func in self.current_functions:
                    if (hasattr(func, 'name') and func.name == func_name) or func_name.startswith("func_"):
                        selected_function = func
                        break
                
                selection_dialog.destroy()
            else:
                messagebox.showwarning("警告", "请选择一个函数")
        
        def on_cancel():
            selection_dialog.destroy()
        
        # 按钮
        ttk.Button(button_frame, text="生成控制流图", command=on_select).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="取消", command=on_cancel).pack(side=tk.RIGHT)
        
        # 默认选择第一个函数
        if self.current_functions:
            tree.selection_set(tree.get_children()[0])
            tree.focus(tree.get_children()[0])
        
        # 双击事件
        tree.bind("<Double-1>", lambda e: on_select())
        
        # 等待对话框关闭
        selection_dialog.wait_window()
        
        return selected_function
    
    def _generate_simple_control_flow_graph(self, selected_func):
        """生成简化的控制流图"""
        try:
            func_name = selected_func.name if hasattr(selected_func, 'name') else "function"
            
            dot_content = f"digraph CFG_{func_name} {{\n"
            dot_content += "    rankdir=TB;\n"
            dot_content += "    node [shape=box, style=filled];\n"
            dot_content += "    edge [color=blue];\n"
            
            # 入口节点
            dot_content += f'    entry [label="Entry\\n{func_name}", fillcolor=lightgreen];\n'
            
            # 基于函数信息生成基本块
            if hasattr(selected_func, 'calls') and selected_func.calls:
                for i, call in enumerate(selected_func.calls[:4]):  # 最多4个调用
                    block_id = f"block_{i}"
                    if 'printf' in call or 'scanf' in call:
                        color = 'lightblue'
                        label = f"I/O操作\\n{call}"
                    elif 'malloc' in call or 'free' in call:
                        color = 'lightyellow'
                        label = f"内存操作\\n{call}"
                    else:
                        color = 'lightgray'
                        label = f"函数调用\\n{call}"
                    
                    dot_content += f'    {block_id} [label="{label}", fillcolor={color}];\n'
                
                # 连接基本块
                dot_content += "    entry -> block_0;\n"
                for i in range(len(selected_func.calls[:4]) - 1):
                    dot_content += f"    block_{i} -> block_{i+1};\n"
                
                # 连接到出口
                last_block = f"block_{min(len(selected_func.calls), 4) - 1}"
                dot_content += f"    {last_block} -> exit;\n"
            else:
                # 没有调用信息时的默认结构
                dot_content += '    process [label="主要逻辑\\nMain Logic", fillcolor=lightgray];\n'
                dot_content += "    entry -> process;\n"
                dot_content += "    process -> exit;\n"
            
            # 出口节点
            dot_content += f'    exit [label="Exit\\n{func_name}", fillcolor=lightcoral];\n'
            
            dot_content += "}\n"
            
            # 使用临时目录保存DOT文件
            temp_dir = get_temp_directory()
            dot_file = os.path.join(temp_dir, f"cfg_{func_name}_{int(time.time())}.dot")
            with open(dot_file, 'w', encoding='utf-8') as f:
                f.write(dot_content)
            
            # 显示可视化窗口
            VisualizationWindow(self.root, f"控制流图 - {func_name}", dot_file)
            
        except Exception as e:
            messagebox.showerror("错误", f"生成简化控制流图失败: {e}")
    
    def show_cwe_analysis(self):
        """显示CWE分析报告"""
        if not self.current_vulnerabilities and not self.current_binary_data:
            messagebox.showwarning("警告", "没有可用的扫描结果，请先扫描文件")
            return
        
        # 创建CWE分析窗口
        cwe_window = tk.Toplevel(self.root)
        cwe_window.title("CWE漏洞分析报告")
        cwe_window.geometry("800x600")
        cwe_window.transient(self.root)
        
        # 主框架
        main_frame = ttk.Frame(cwe_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(main_frame, text="🛡️ CWE漏洞分析报告", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # 创建Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # CWE统计标签页
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="CWE统计")
        
        # 统计信息
        cwe_stats = self._analyze_cwe_statistics()
        stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        stats_content = "CWE漏洞分类统计:\n\n"
        for cwe_id, count in cwe_stats.items():
            cwe_info = CWEDatabase.get_cwe_info(cwe_id)
            stats_content += f"{cwe_id}: {cwe_info.get('name', 'Unknown')} - {count} 个\n"
            stats_content += f"  严重性: {cwe_info.get('severity', 'Unknown')}\n"
            stats_content += f"  分类: {cwe_info.get('category', 'Unknown')}\n\n"
        
        stats_text.insert(tk.END, stats_content)
        stats_text.config(state=tk.DISABLED)
        
        # CWE详细信息标签页
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="CWE详细信息")
        
        details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
        details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        details_content = "CWE漏洞详细信息:\n\n"
        for vuln in self.current_vulnerabilities:
            if hasattr(vuln, 'category') and vuln.category and vuln.category.cwe_id:
                cwe_info = CWEDatabase.get_cwe_info(vuln.category.cwe_id)
                details_content += f"漏洞: {vuln.name}\n"
                details_content += f"CWE: {vuln.category.cwe_id} - {cwe_info.get('name', 'Unknown')}\n"
                details_content += f"描述: {cwe_info.get('description', 'No description')}\n"
                details_content += f"缓解措施: {cwe_info.get('mitigation', 'No mitigation')}\n"
                details_content += "-" * 80 + "\n\n"
        
        details_text.insert(tk.END, details_content)
        details_text.config(state=tk.DISABLED)
        
        # 关闭按钮
        close_button = ttk.Button(main_frame, text="关闭", command=cwe_window.destroy)
        close_button.pack(pady=(10, 0))
    
    def _analyze_cwe_statistics(self) -> Dict[str, int]:
        """分析CWE统计信息"""
        cwe_stats = {}
        
        for vuln in self.current_vulnerabilities:
            if hasattr(vuln, 'category') and vuln.category and vuln.category.cwe_id:
                cwe_id = vuln.category.cwe_id
                cwe_stats[cwe_id] = cwe_stats.get(cwe_id, 0) + 1
        
        return cwe_stats
    
    def _safe_quit(self):
        """安全退出程序"""
        try:
            # 清理临时文件
            cleanup_temp_files()
        except Exception as e:
            logger.warning(f"退出清理失败: {e}")
        finally:
            self.root.quit()
    
    def run(self):
        """运行应用程序"""
        # 设置窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._safe_quit)
        self.root.mainloop()


def main():
    """主函数"""
    try:
        app = BinaryVulnScannerGUI()
        app.run()
    except Exception as e:
        print(f"启动图形界面失败: {e}")
        print("请确保已安装 tkinter 库")
        sys.exit(1)


if __name__ == "__main__":
    main()
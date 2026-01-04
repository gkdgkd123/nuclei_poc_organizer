#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nuclei POC Organizer & Deduplicator
===================================
一个用于整理 Nuclei POC YAML 文件的的高级工具。
Author：GKDf1sh
https://github.com/gkdgkd123/nuclei_poc_organize

功能特点 (Features):
  1. 智能去重 (Intelligent Deduplication):
     - 基于 MD5 哈希的精确去重。
     - 基于 Jaccard 相似度的逻辑去重 (识别不同写法的同一POC)。
  2. 鲁棒分类 (Robust Classification):
     - 自动按 Severity (严重等级) 分类。
     - 双重解析引擎 (YAML Safe Load + Regex Fallback)，最大限度挽救格式错误的 POC。
  3. WordPress 专区 (WordPress Separation):
     - 自动识别 WordPress 相关 POC 并将其隔离到独立目录。
  4. 冲突处理 (Conflict Resolution):
     - 同名文件自动保留体积最大者 (Size-based retention)。
     - 严格禁止生成 '_1', '_2' 等冗余后缀。

用法 (Usage):
  python3 nuclei_poc_organizer.py -i <source_dir> -o <output_dir>

依赖 (Requirements):
  pip install PyYAML
"""

import os
import sys
import shutil
import hashlib
import re
import time
import logging
import argparse
from typing import Set, List, Dict, Tuple, Optional

# 配置日志格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("NucleiOrganizer")

# 尝试导入 PyYAML，如果失败则提示
try:
    import yaml
except ImportError:
    logger.error("缺少必要依赖: PyYAML")
    print("请运行: pip install PyYAML")
    sys.exit(1)


class NucleiOrganizer:
    def __init__(self, src_dir: str, dst_dir: str):
        self.src_dir = os.path.abspath(src_dir)
        self.dst_dir = os.path.abspath(dst_dir)
        
        # 统计面板
        self.stats = {
            'scanned': 0,
            'unique_kept': 0,
            'dedup_similarity': 0,  # 逻辑相似去除
            'dedup_md5': 0,         # MD5去除
            'conflict_overwritten': 0, # 覆盖小文件
            'conflict_skipped': 0,     # 保留大文件
            'regex_rescued': 0,     # 正则挽救计数
            'wordpress_found': 0,
            'errors': 0
        }

        self.hash_map = set()  # 全局MD5记录
        
        # 忽略词集合 (用于逻辑去重，过滤掉通用语法词，只保留特征词)
        self.stop_words = {
            'method', 'get', 'post', 'path', 'baseurl', 'host', 'user-agent', 
            'matchers', 'condition', 'status', 'type', 'word', 'body', 
            'requests', 'http', 'raw', 'info', 'id', 'name', 'author',
            'severity', 'description', 'reference', 'tags', 'metadata'
        }

        # 严重等级白名单
        self.valid_severities = {
            'critical', 'high', 'medium', 'low', 'info', 'unknown'
        }

    def _calculate_md5(self, content: str) -> str:
        """计算去除空白字符后的内容 MD5"""
        cleaned = re.sub(r'\s+', '', content)
        return hashlib.md5(cleaned.encode('utf-8')).hexdigest()

    def _extract_feature_set(self, content: str) -> Set[str]:
        """
        提取 POC 的逻辑特征指纹 (Feature Fingerprint)。
        用于计算 Jaccard 相似度，识别写法不同但逻辑相同的 POC。
        """
        try:
            # 提取所有长度大于4的字母数字组合、路径片段
            # 这种方式能同时捕获 URL 路径、参数名和特定的匹配关键字
            tokens = re.findall(r'[a-zA-Z0-9_\-\.\/]{4,}', content)
            feature_set = set()
            for token in tokens:
                t_lower = token.lower()
                if t_lower not in self.stop_words:
                    feature_set.add(t_lower)
            return feature_set
        except Exception:
            return set()

    def _calculate_jaccard(self, set1: Set[str], set2: Set[str]) -> float:
        """计算两个特征集合的 Jaccard 相似度 (0.0 - 1.0)"""
        if not set1 or not set2:
            return 0.0
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0.0

    def _is_wordpress(self, content: str, filename: str) -> bool:
        """
        检测是否为 WordPress 相关的 POC。
        策略：检查文件名关键字 + 内容路径特征。
        """
        content_lower = content.lower()
        filename_lower = filename.lower()

        # 1. 文件名强匹配
        if 'wordpress' in filename_lower or 'wp-' in filename_lower:
            return True
        
        # 2. 内容路径特征强匹配
        if '/wp-content/' in content_lower or \
           '/wp-admin/' in content_lower or \
           '/wp-includes/' in content_lower or \
           '/wp-json/' in content_lower:
            return True
            
        # 3. 标签匹配 (正则)
        if re.search(r'tags:\s*.*wordpress', content_lower):
            return True
            
        return False

    def _get_severity_robust(self, content: str) -> Tuple[str, bool]:
        """
        鲁棒地获取 Severity。
        Returns: (severity, is_rescued_by_regex)
        """
        # 策略A: 标准 YAML 解析 (为了速度只取前 2KB)
        try:
            head_content = content if len(content) < 2048 else content[:2048] + "\n"
            # 使用 SafeLoader 防止代码执行风险
            data = yaml.safe_load(head_content)
            if isinstance(data, dict):
                sev = data.get('info', {}).get('severity', None)
                if sev:
                    return str(sev).lower(), False
        except (yaml.YAMLError, AttributeError):
            pass  # 解析失败，静默降级到策略 B
            
        # 策略B: 正则表达式兜底 (挽救格式错误的 YAML)
        try:
            match = re.search(r'severity:\s*([a-zA-Z]+)', content, re.IGNORECASE)
            if match:
                return match.group(1).lower(), True
        except Exception:
            pass
            
        return 'unknown', False

    def _get_base_filename(self, filename: str) -> str:
        """
        获取规范化的基础文件名。
        移除常见的重复后缀 (如 _1, -1, .1)。
        Ex: cve-2023-001_1.yaml -> cve-2023-001.yaml
        """
        # 匹配模式：文件名 + 可选的分隔符和1-3位数字 + 扩展名
        match = re.match(r'^(.*?)(?:[-_.]\d{1,3})?(\.ya?ml)$', filename, re.IGNORECASE)
        if match:
            return f"{match.group(1)}{match.group(2)}"
        return filename

    def group_files_by_name(self) -> Dict[str, List[str]]:
        """
        第一阶段：扫描源目录，按“规范化文件名”进行分组。
        """
        groups = {}
        for root, _, files in os.walk(self.src_dir):
            # 防止死循环：跳过输出目录
            if self.dst_dir in os.path.abspath(root):
                continue
                
            for file in files:
                if file.lower().endswith(('.yaml', '.yml')):
                    self.stats['scanned'] += 1
                    path = os.path.join(root, file)
                    base = self._get_base_filename(file)
                    
                    if base not in groups:
                        groups[base] = []
                    groups[base].append(path)
        return groups

    def _smart_copy(self, src_path: str, dst_path: str, src_size: int):
        """
        智能复制策略：同名文件保留体积大者。
        """
        try:
            if os.path.exists(dst_path):
                dst_size = os.path.getsize(dst_path)
                if src_size > dst_size:
                    # 源文件更大 -> 覆盖旧文件
                    shutil.copy2(src_path, dst_path)
                    self.stats['conflict_overwritten'] += 1
                    # 这里计数逻辑：虽然是覆盖，但也算保留了一个 Unique
                else:
                    # 现有文件更大或相等 -> 跳过源文件
                    self.stats['conflict_skipped'] += 1
            else:
                # 目标不存在 -> 直接复制
                shutil.copy2(src_path, dst_path)
                self.stats['unique_kept'] += 1
        except Exception as e:
            logger.error(f"复制文件失败 {src_path}: {e}")
            self.stats['errors'] += 1

    def process_group(self, base_name: str, file_list: List[str]):
        """
        核心处理逻辑：处理单个同名文件组。
        流程: 组内逻辑去重 -> 全局MD5去重 -> 分类 -> 智能复制
        """
        if not file_list:
            return

        # 1. 预读取所有文件内容 (Batch Read)
        file_data = []
        for fpath in file_list:
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                file_data.append({
                    'path': fpath,
                    'content': content,
                    'features': self._extract_feature_set(content),
                    'hash': self._calculate_md5(content),
                    'size': len(content)
                })
            except Exception:
                self.stats['errors'] += 1

        if not file_data:
            return

        # 2. 组内相似度聚类 (Jaccard Clustering)
        candidates = []
        
        if len(file_data) == 1:
            # 只有一个文件，无需聚类，直接作为候选
            best = file_data[0]
            best['target_name'] = base_name  # 强制使用规范化名称
            candidates.append(best)
        else:
            # 多文件对比
            remaining = file_data[:]
            while remaining:
                base = remaining.pop(0)
                cluster = [base]
                non_similar = []
                
                for other in remaining:
                    sim = self._calculate_jaccard(base['features'], other['features'])
                    # 阈值 0.7: 逻辑极其相似即视为同一个POC
                    if sim >= 0.7:
                        cluster.append(other)
                    else:
                        non_similar.append(other)
                
                remaining = non_similar
                
                if len(cluster) > 1:
                    self.stats['dedup_similarity'] += (len(cluster) - 1)
                
                # 组内优选：体积最大者 (Size Max)
                best_file = max(cluster, key=lambda x: x['size'])
                best_file['target_name'] = base_name
                candidates.append(best_file)

        # 3. 全局 MD5 去重 & 分类处理
        for item in candidates:
            # MD5 全局查重
            if item['hash'] in self.hash_map:
                self.stats['dedup_md5'] += 1
                continue
            
            self.hash_map.add(item['hash'])
            
            # 获取等级
            severity, rescued = self._get_severity_robust(item['content'])
            if severity not in self.valid_severities:
                severity = 'unknown'
            if rescued:
                self.stats['regex_rescued'] += 1
            
            # 检测 WordPress
            is_wp = self._is_wordpress(item['content'], base_name)
            
            # 构建目标路径结构: output / [wordpress] / severity / filename
            if is_wp:
                self.stats['wordpress_found'] += 1
                target_folder = os.path.join(self.dst_dir, "wordpress", severity)
            else:
                target_folder = os.path.join(self.dst_dir, severity)
                
            if not os.path.exists(target_folder):
                os.makedirs(target_folder, exist_ok=True)
                
            dest_path = os.path.join(target_folder, item['target_name'])
            
            # 执行智能复制
            self._smart_copy(item['path'], dest_path, item['size'])

    def run(self):
        """执行主流程"""
        start_time = time.time()
        
        print("="*60)
        print(f"Nuclei POC Organizer 启动")
        print(f"源目录: {self.src_dir}")
        print(f"输出目录: {self.dst_dir}")
        print("="*60)
        
        if not os.path.exists(self.src_dir):
            logger.error(f"源目录不存在: {self.src_dir}")
            return

        # 1. 扫描分组
        logger.info("阶段 1/2: 扫描源文件并按名称分组...")
        file_groups = self.group_files_by_name()
        total_groups = len(file_groups)
        logger.info(f"扫描完成: 发现 {self.stats['scanned']} 个文件，聚合为 {total_groups} 个同名组")
        
        # 2. 并行/流式处理
        logger.info("阶段 2/2: 执行去重、分类与整理...")
        count = 0
        
        for base_name, files in file_groups.items():
            self.process_group(base_name, files)
            count += 1
            
            # 进度条
            if count % 100 == 0 or count == total_groups:
                sys.stdout.write(
                    f"\r[进度] {count}/{total_groups} | "
                    f"留存: {self.stats['unique_kept']} | "
                    f"WP: {self.stats['wordpress_found']} | "
                    f"去重: {self.stats['dedup_md5'] + self.stats['dedup_similarity']}"
                )
                sys.stdout.flush()
        
        print("\n")
        self._print_report(time.time() - start_time)

    def _print_report(self, duration: float):
        """打印最终报告"""
        print("\n" + "="*60)
        print(f" 处理完成报告 (耗时: {duration:.2f}s)")
        print(f" 扫描文件总数: {self.stats['scanned']}")
        print(f" 最终留存文件: {self.stats['unique_kept']} (位于 {self.dst_dir})")
        print("-" * 30)
        print(f" [去重统计]")
        print(f"   ├─ 逻辑相似剔除 (Jaccard): {self.stats['dedup_similarity']}")
        print(f"   └─ 内容完全重复 (MD5):     {self.stats['dedup_md5']}")
        print("-" * 30)
        print(f" [冲突解决 (同名处理)]")
        print(f"   ├─ 覆盖旧文件 (保留体积更大): {self.stats['conflict_overwritten']}")
        print(f"   └─ 跳过新文件 (保留现有更大): {self.stats['conflict_skipped']}")
        print("-" * 30)
        print(f" [分类统计]")
        print(f"   ├─ WordPress POC:          {self.stats['wordpress_found']}")
        print(f"   └─ 正则挽救 (YAML解析失败): {self.stats['regex_rescued']}")
        print("-" * 30)
        print(f" [错误]")
        print(f"   └─ 读写/权限错误:           {self.stats['errors']}")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="Nuclei POC 整理工具 - 去重、分类与标准化",
        epilog="示例: python3 nuclei_organizer.py -i ./raw_pocs -o ./clean_pocs"
    )
    
    # 强制参数，不设置默认值
    parser.add_argument("-i", "--input", required=True, help="输入 POC 根目录 (源)")
    parser.add_argument("-o", "--output", required=True, help="输出 POC 根目录 (目标)")
    
    args = parser.parse_args()
    
    organizer = NucleiOrganizer(args.input, args.output)
    organizer.run()

if __name__ == "__main__":
    main()

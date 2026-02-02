#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import math
import socket
import time
import random
import argparse
import ipaddress
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Tuple

# ===========================
# 1. 配置
# ===========================

DEFAULT_CONFIG = {
    "threads": 500,
    "timeout": 1.0,
    "test_count": 10000,      # 目标 TCP 扫描数量
    "port": 443,
    "speed_test_range": 20,
    "min_speed_target": 5.0,
    "ipv6_enabled": False,
    "decay_rate": 0.85
}

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4/"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6/"

CONFIG_FILE = "config.json"
MODEL_FILE = "ucb_model.json"
TRACE_FILE = "trace.log"
IPV4_FILE = "ipv4.txt"
IPV6_FILE = "ipv6.txt"
RESULT_FILE = "result.csv"

# ===========================
# 2. UCB 智能算法 (V5.2: 冷启动保护)
# ===========================

class UCBManager:
    def __init__(self, decay_rate=0.85):
        self.decay_rate = decay_rate
        self.data = {
            "version": 5,
            "total_runs": 0,    # 这里的 total_runs 指的是累积测试过的 IP 总数
            "launch_count": 0,  # [新增] 程序启动次数
            "subnets": {}       
        }
        self.load()
        # 每次实例化（程序启动）增加计数
        self.data["launch_count"] = self.data.get("launch_count", 0) + 1

    def load(self):
        if os.path.exists(MODEL_FILE):
            try:
                with open(MODEL_FILE, 'r') as f:
                    self.data = json.load(f)
            except: pass

    def save(self):
        # 仅衰减权重，不衰减启动次数
        self.data["total_runs"] *= self.decay_rate
        
        to_remove = []
        for net, record in self.data["subnets"].items():
            record["count"] *= self.decay_rate
            record["total_reward"] *= self.decay_rate
            
            avg = record["total_reward"] / record["count"] if record["count"] > 0 else 0
            if record["count"] < 0.5 and avg < 0.2:
                to_remove.append(net)
        
        for net in to_remove:
            del self.data["subnets"][net]

        try:
            with open(MODEL_FILE, 'w') as f:
                json.dump(self.data, f)
        except: pass

    def is_cold_start(self) -> bool:
        """
        判断是否处于冷启动阶段
        条件：启动次数 <= 3 或者 历史累积测试样本极少
        """
        launch = self.data.get("launch_count", 1)
        # 如果是前3次运行，或者模型里几乎没有数据
        if launch <= 3 or len(self.data["subnets"]) < 100:
            return True
        return False

    def update(self, ip: str, latency: float, speed: float = 0.0, is_loss: bool = False, tcp_only: bool = False):
        try:
            if ':' in ip: return
            net = str(ipaddress.IPv4Network(ip + "/24", strict=False).network_address)
        except: return

        if is_loss:
            current_reward = 0.0
        else:
            r_latency = 0.3 * (1.0 - min(max(latency - 50, 0) / 150.0, 1.0))
            if tcp_only:
                current_reward = r_latency
            else:
                r_speed = 0.7 * min(speed / 10.0, 1.0)
                current_reward = r_latency + r_speed

        if net not in self.data["subnets"]:
            self.data["subnets"][net] = {"count": 0, "total_reward": 0.0}
        record = self.data["subnets"][net]

        impact_weight = 1.0 
        if record["count"] > 2.0:
            avg_score = record["total_reward"] / record["count"]
            if avg_score > 0.6 and current_reward < 0.1:
                impact_weight = 0.2 

        record["count"] += impact_weight
        record["total_reward"] += (current_reward * impact_weight)
        self.data["total_runs"] += impact_weight

    def get_score(self, subnet_ip: str) -> float:
        record = self.data["subnets"].get(subnet_ip)
        # 给予未探索网段极高的初始分，确保它们有机会被选中
        if not record or record["count"] < 0.1:
            return 9999.0 
        
        n = max(self.data["total_runs"], 1.0)
        nj = record["count"]
        avg_reward = record["total_reward"] / nj
        exploration = math.sqrt(2 * math.log(n) / nj)
        return avg_reward + exploration

# ===========================
# 3. 基础工具
# ===========================

class Logger:
    @staticmethod
    def info(msg): print(f"[INFO] {msg}")
    @staticmethod
    def error(msg): print(f"[ERROR] {msg}")
    
    @staticmethod
    def log_result(best_ips: List):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if os.path.exists(TRACE_FILE) and os.path.getsize(TRACE_FILE) > 1024 * 1024:
            try:
                with open(TRACE_FILE, 'r', encoding='utf-8') as f: lines = f.readlines()
                with open(TRACE_FILE, 'w', encoding='utf-8') as f: f.writelines(lines[-50:])
            except: pass

        try:
            with open(TRACE_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] Top Results:\n")
                for ip in best_ips:
                    f.write(f"  - {ip.ip:<15} | {ip.latency:.1f}ms | {ip.speed:.2f}MB/s\n")
                f.write("\n")
        except: pass

class ConfigManager:
    def __init__(self, fix_conf):
        self.config = DEFAULT_CONFIG
        self.fix_conf = fix_conf
        self.load()
    
    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config.update(json.load(f))
            except:
                if self.fix_conf: self.save()
                else: sys.exit(1)
        else:
            self.save()

    def save(self):
        with open(CONFIG_FILE, 'w') as f: json.dump(self.config, f, indent=4)

class IPManager:
    @staticmethod
    def fetch(url, fname):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as r:
                with open(fname, 'w') as f: f.write(r.read().decode('utf-8'))
        except: pass

    @staticmethod
    def load(fname, is_v6):
        if not os.path.exists(fname): return []
        nets = []
        with open(fname, 'r') as f:
            for line in f:
                try:
                    n = ipaddress.ip_network(line.strip(), strict=False)
                    if (is_v6 and n.version == 6) or (not is_v6 and n.version == 4):
                        nets.append(n)
                except: continue
        return nets

# ===========================
# 4. 智能生成器 (V5.2: 冷启动逻辑)
# ===========================

class SmartGenerator:
    @staticmethod
    def generate(cidrs_v4, cidrs_v6, max_total_count, ucb: UCBManager):
        targets = []
        
        # 1. 展开所有 IPv4 子网
        all_subnets = []
        if cidrs_v4:
            for net in cidrs_v4:
                if net.prefixlen < 24:
                    all_subnets.extend(list(net.subnets(new_prefix=24)))
                else:
                    all_subnets.append(net)
        
        # === 冷启动检测 ===
        if ucb.is_cold_start():
            Logger.info(f"检测到冷启动阶段 (第 {ucb.data.get('launch_count', 1)} 次运行)。")
            Logger.info(f"执行强制普查模式，目标生成数量: {max_total_count}")
            
            # 冷启动策略：完全随机，不看权重，确保覆盖面
            # 从所有子网中随机抽取 max_total_count 个 IP
            # 为了保证每个子网都有机会，我们先打乱子网
            random.shuffle(all_subnets)
            
            # 循环抽取直到满足数量
            while len(targets) < max_total_count:
                for sn in all_subnets:
                    if len(targets) >= max_total_count: break
                    if sn.num_addresses > 2:
                        rip = str(sn[random.randint(1, sn.num_addresses - 2)])
                        targets.append(rip)
                
                # 如果一轮不够（比如 max_count 很大），就再来一轮
                if len(targets) >= max_total_count: break
                
                # 如果子网数量太少，无法生成足够的不重复IP，则退出防止死循环
                if len(all_subnets) * 254 < max_total_count and len(targets) >= len(all_subnets) * 250:
                    break

        else:
            # === 正常 UCB 模式 ===
            Logger.info("正在评估网段质量并分配预算 (UCB Mode)...")
            
            scored_subnets = []
            for sn in all_subnets:
                score = ucb.get_score(str(sn.network_address))
                scored_subnets.append((score, sn))
            
            scored_subnets.sort(key=lambda x: x[0], reverse=True)
            total_subnets = len(scored_subnets)
            
            stats = {"elite": 0, "good": 0, "normal": 0, "explore": 0}
            generated_count = 0
            
            for rank, (score, sn) in enumerate(scored_subnets):
                if generated_count >= max_total_count: break
                
                if rank < total_subnets * 0.05:   # Top 5%
                    count = 5
                    stats["elite"] += 1
                elif rank < total_subnets * 0.20: # Top 20%
                    count = 3
                    stats["good"] += 1
                elif rank < total_subnets * 0.50: # Top 50%
                    count = 1
                    stats["normal"] += 1
                else:                             # Bottom 50%
                    if random.random() < 0.01:    # 1% 复活
                        count = 1
                        stats["explore"] += 1
                    else:
                        count = 0
                
                if count > 0:
                    real_count = min(count, sn.num_addresses - 2) if sn.num_addresses > 2 else 1
                    picked = set()
                    for _ in range(real_count):
                        for _ in range(5):
                            rip = str(sn[random.randint(1, sn.num_addresses - 2)])
                            if rip not in picked:
                                picked.add(rip)
                                targets.append(rip)
                                generated_count += 1
                                break
            
            Logger.info(f"预算分配: 精英[{stats['elite']}] 优质[{stats['good']}] 普通[{stats['normal']}] 探索[{stats['explore']}]")

        # IPv6 处理 (冷启动时也应该包含)
        if cidrs_v6:
            limit = int(max_total_count * 0.1)
            for _ in range(limit):
                cidr = random.choice(cidrs_v6)
                base = int(cidr.network_address)
                targets.append(str(ipaddress.IPv6Address(base + random.randint(1, 2**16))))

        Logger.info(f"最终生成目标: {len(targets)} 个")
        random.shuffle(targets)
        return targets

# ===========================
# 5. 测速引擎
# ===========================

class IpResult:
    def __init__(self, ip, latency=0.0, speed=0.0, loss=False):
        self.ip = ip
        self.latency = latency
        self.speed = speed
        self.loss = loss
    
    def __lt__(self, other):
        if self.loss != other.loss: return not self.loss
        return self.latency < other.latency

class Scanner:
    def __init__(self, config, targets, ucb: UCBManager):
        self.config = config
        self.targets = targets
        self.ucb = ucb
        self.results = []

    def _tcp(self, ip):
        try:
            s = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.config['timeout'])
            st = time.time()
            res = s.connect_ex((ip, self.config['port']))
            s.close()
            return IpResult(ip, (time.time()-st)*1000) if res == 0 else IpResult(ip, loss=True)
        except: return IpResult(ip, loss=True)

    def _http(self, ip):
        try:
            url = f"http://{'['+ip+']' if ':' in ip else ip}/__down?bytes={20*1024*1024}"
            req = urllib.request.Request(url, headers={"Host": "speed.cloudflare.com", "User-Agent": "CF-UCB"})
            st = time.time()
            with urllib.request.urlopen(req, timeout=4) as r:
                tot = 0
                while True:
                    d = r.read(65536)
                    if not d: break
                    tot += len(d)
                    if time.time()-st > 3: break
            dur = time.time()-st
            return (tot/1048576)/dur if dur > 0 else 0
        except: return 0

    def run(self):
        if not self.targets: return
        Logger.info(f"启动 TCP 扫描 ({self.config['threads']} 线程)...")
        
        valid = []
        with concurrent.futures.ThreadPoolExecutor(self.config['threads']) as ex:
            futs = {ex.submit(self._tcp, ip): ip for ip in self.targets}
            done = 0
            total = len(self.targets)
            for f in concurrent.futures.as_completed(futs):
                done += 1
                if done % 1000 == 0 or done == total: 
                    print(f"[*] 进度: {done}/{total}", end="\r")
                r = f.result()
                
                self.ucb.update(r.ip, r.latency, speed=0.0, is_loss=r.loss, tcp_only=True)
                if not r.loss: valid.append(r)
        
        print("\n")
        valid.sort()
        self.results = valid
        Logger.info(f"TCP 存活: {len(valid)}")

    def smart_speed_test(self):
        cands = self.results[:self.config['speed_test_range']]
        if not cands: return

        print(f"\n>>> UCB 评估 Top {len(cands)} 并更新模型 <<<")
        print(f"{'IP Address':<25} | {'Latency':<10} | {'Speed':<10}")
        print("-" * 50)

        final = []
        target = self.config.get('min_speed_target', 5.0)

        for r in cands:
            s = self._http(r.ip)
            r.speed = s
            print(f"{r.ip:<25} | {r.latency:.2f} ms   | {s:.2f} MB/s")
            
            self.ucb.update(r.ip, r.latency, speed=s, is_loss=False, tcp_only=False)
            if s > 0.1: final.append(r)
        
        self.ucb.save()

        final.sort(key=lambda x: x.speed, reverse=True)
        high_quality = [x for x in final if x.speed >= target]
        if len(high_quality) < 5:
            remain = [x for x in final if x not in high_quality]
            high_quality.extend(remain[:5-len(high_quality)])
        
        print("-" * 50)
        print(f"最终优选:")
        for r in high_quality:
            icon = "🚀" if r.speed >= target else "✅"
            print(f"{icon} {r.ip:<23} | {r.latency:.2f} ms   | {r.speed:.2f} MB/s")

        Logger.log_result(high_quality)

        try:
            with open(RESULT_FILE, "w") as f:
                f.write("IP,Latency,Speed\n")
                for r in high_quality: f.write(f"{r.ip},{r.latency:.2f},{r.speed:.2f}\n")
            Logger.info(f"结果已保存: {RESULT_FILE}")
        except: pass

# ===========================
# 6. 入口
# ===========================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fix_conf", action="store_true")
    parser.add_argument("--ipv6", nargs='?', const='both')
    args = parser.parse_args()

    cm = ConfigManager(args.fix_conf)
    decay = cm.config.get('decay_rate', 0.85)
    ucb = UCBManager(decay_rate=decay)

    if not os.path.exists(IPV4_FILE): IPManager.fetch(CF_IPV4_URL, IPV4_FILE)
    if not os.path.exists(IPV6_FILE): IPManager.fetch(CF_IPV6_URL, IPV6_FILE)

    v4 = IPManager.load(IPV4_FILE, False) if args.ipv6 != 'only' else []
    v6 = IPManager.load(IPV6_FILE, True) if args.ipv6 else []

    if not v4 and not v6: sys.exit(1)

    targets = SmartGenerator.generate(v4, v6, cm.config['test_count'], ucb)
    
    scanner = Scanner(cm.config, targets, ucb)
    scanner.run()
    scanner.smart_speed_test()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)

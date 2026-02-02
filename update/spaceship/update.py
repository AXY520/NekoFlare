import csv
import requests
import logging
import sys

# ================= 🔧 配置区域 =================

# CSV文件路径
CSV_FILE = 'result.csv'

# Spaceship API 凭证
API_KEY = "你的_API_KEY"
API_SECRET = "你的_API_SECRET"

# 主域名 (Zone)
DOMAIN = "example.com"

# 需要更新的子域名列表 (填写相对于主域名的 Host 部分)
# 示例：
# - 更新 example.com -> "@"
# - 更新 www.example.com -> "www"
# - 更新 vpn.bj.example.com -> "vpn.bj"
# - 更新 *.cdn.example.com -> "*.cdn"
SUBDOMAINS = ["@", "www", "vpn.bj", "*.cdn"]

# 最大 IP 数量限制 (脚本会取：实际有效IP数 和 此数值 的较小值)
MAX_IP_COUNT = 5

# TTL 设置
TTL = 300

# Spaceship API 地址
API_BASE_URL = "https://spaceship.dev/api/v1/dns/records"

# ================= 🚀 脚本逻辑 =================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_best_ips(csv_path):
    """
    读取 CSV 返回所有有效 IP，按质量排序
    """
    ips = []
    try:
        with open(csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    # 过滤掉无效数据
                    if not row['IP']: continue
                    
                    ip_info = {
                        "ip": row['IP'],
                        "latency": float(row['Latency']),
                        "speed": float(row['Speed'])
                    }
                    ips.append(ip_info)
                except (ValueError, KeyError):
                    continue
        
        # 排序：速度降序(-)，延迟升序(+)
        ips.sort(key=lambda x: (-x['speed'], x['latency']))
        
        # 提取纯 IP 列表
        sorted_ips = [x['ip'] for x in ips]
        logging.info(f"📊 CSV读取完成，共找到 {len(sorted_ips)} 个有效 IP")
        return sorted_ips
        
    except FileNotFoundError:
        logging.error(f"❌ 找不到文件: {csv_path}")
        return []
    except Exception as e:
        logging.error(f"❌ 读取 CSV 出错: {e}")
        return []

class SpaceshipDNS:
    def __init__(self, domain, api_key, api_secret):
        self.domain = domain
        self.headers = {
            "X-API-Key": api_key,
            "X-API-Secret": api_secret,
            "Content-Type": "application/json"
        }
        self.url = f"{API_BASE_URL}/{domain}"

    def get_records(self):
        try:
            params = {"take": 500} # 尽量获取所有记录
            resp = requests.get(self.url, headers=self.headers, params=params)
            resp.raise_for_status()
            return resp.json().get('items', [])
        except Exception as e:
            logging.error(f"获取 DNS 记录失败: {e}")
            return []

    def update_records(self, records_to_delete, records_to_add):
        """
        Spaceship API 通常分两步：先删后加，或者使用 PUT 覆盖
        为了安全起见，这里演示 1.删除旧的 2.添加新的
        """
        # 1. 删除旧记录
        if records_to_delete:
            try:
                logging.info(f"🗑️ 正在删除 {len(records_to_delete)} 条旧记录...")
                del_payload = {"items": records_to_delete}
                # 注意：DELETE 请求通常需要传完整的对象或ID，这里传 items
                requests.delete(self.url, headers=self.headers, json=del_payload)
            except Exception as e:
                logging.error(f"删除记录出错: {e}")

        # 2. 添加新记录
        if records_to_add:
            try:
                logging.info(f"✅ 正在添加 {len(records_to_add)} 条新记录...")
                put_payload = {
                    "force": True, # 强制写入
                    "items": records_to_add
                }
                requests.put(self.url, headers=self.headers, json=put_payload)
            except Exception as e:
                logging.error(f"添加记录出错: {e}")

def main():
    # 1. 获取所有可用 IP
    all_best_ips = get_best_ips(CSV_FILE)
    if not all_best_ips:
        sys.exit(1)

    # 2. 动态确定本次使用的 IP 列表
    # 取 "CSV里有的" 和 "最大限制" 之间的较小值
    count_to_use = min(len(all_best_ips), MAX_IP_COUNT)
    target_ips = all_best_ips[:count_to_use]
    
    logging.info(f"🎯 本次将更新 {count_to_use} 个 IP: {target_ips}")

    # 3. 初始化 API
    client = SpaceshipDNS(DOMAIN, API_KEY, API_SECRET)
    
    # 4. 获取当前线上记录
    current_records = client.get_records()
    
    records_to_delete = []
    records_to_add = []

    # 5. 构建更新计划
    for sub in SUBDOMAINS:
        logging.info(f"🔍 分析子域: {sub}")
        
        # --- A. 找出该子域下需要删除的旧 A 记录 ---
        # 逻辑：只要是 Type=A 且 Name=sub 的，全部列入删除计划
        # (这样可以确保彻底清除旧的、慢的 IP，防止残留)
        for record in current_records:
            if record.get('type') == 'A' and record.get('name') == sub:
                # 记录下需要删除的完整对象
                records_to_delete.append(record)

        # --- B. 为该子域生成新的 A 记录 ---
        for ip in target_ips:
            new_record = {
                "type": "A",
                "name": sub,
                "address": ip, # 如果报错，请尝试改为 "content": ip
                "ttl": TTL
            }
            records_to_add.append(new_record)

    # 6. 执行更新
    if not records_to_delete and not records_to_add:
        logging.info("无需任何变更")
        return

    # 优化：如果新旧 IP 完全一致（集合比较），则跳过更新，减少 API 调用
    # 这里为了代码简洁，略过复杂的 Diff 对比，直接执行“先删后加”通常最稳妥
    
    client.update_records(records_to_delete, records_to_add)
    logging.info("🎉 所有子域更新完成")

if __name__ == "__main__":
    main()

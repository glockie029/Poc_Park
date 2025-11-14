import re

# 打开文件并读取内容
file_path = 'target.txt'  # 替换成你的文件路径
with open(file_path, 'r') as file:
    text = file.read()

# 使用正则表达式查找包含http://或https://前缀的域名，包括IP地址形式的域名
domain_pattern = r'https?://(?:[a-zA-Z0-9.-]+|(?:\d{1,3}\.){3}\d{1,3})'
domains = re.findall(domain_pattern, text)

# 去重域名
unique_domains = set(domains)

# 打印提取到的域名
for domain in unique_domains:
    print(domain)
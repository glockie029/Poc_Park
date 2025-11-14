# 定义颜色代码变量
red = "\033[1;31m"
green = "\033[1;32m"
yellow = "\033[1;33m"
blue = "\033[1;34m"
magenta = "\033[1;35m"
cyan = "\033[1;36m"
white = "\033[1;37m"

# 定义背景颜色代码变量
red_background = "\033[1;41m"
green_background = "\033[1;42m"
yellow_background = "\033[1;43m"
blue_background = "\033[1;44m"
magenta_background = "\033[1;45m"
cyan_background = "\033[1;46m"
white_background = "\033[1;47m"

# 定义样式代码变量
bold = "\033[1m"
italic = "\033[3m"
underline = "\033[4m"

# 定义重置颜色代码变量
reset = "\033[0m"

# 示例使用颜色代码变量
text = f"{red}This is red text.{reset}"
background = f"{green_background}Green background.{reset}"
style = f"{bold}{underline}Bold and underlined text.{reset}"

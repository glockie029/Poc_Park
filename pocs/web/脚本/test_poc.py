import argparse
import pyfiglet
import color
from colorama import Fore, Back, Style, init


def main():
    # 初始化colorama以允许颜色输出
    init(autoreset=True)

    # 创建ASCII艺术字
    text = "G l o c k"
    ascii_art = pyfiglet.figlet_format(text, font="doom")

    # 定义颜色列表
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE]

    # 用不同颜色着色每个字符
    colored_ascii_art = ""
    color_index = 0

    for char in ascii_art:
        if char != " ":
            colored_ascii_art += colors[color_index % len(colors)] + char
            color_index += 1
        else:
            colored_ascii_art += char

    # 打印带颜色的ASCII艺术字
    # print(colored_ascii_art)
    parser = argparse.ArgumentParser()
    print(colored_ascii_art, end='')
    parser.add_argument('-i','--input', help=' 文件名')
    # parser.add_argument('-a', '--all', help="查看帮助")
    parser.add_argument('-f', '--file', help="读取文件内容")

    args = parser.parse_args()

    if args.all:
        print(f"指定的文件名是:{args.all}")
    if args.file:
        print(f"指定的目录:{args.file}")


#
if __name__ == "__main__":
    main()

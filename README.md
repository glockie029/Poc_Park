# pocsuite_pocs
使用方法:
```
单个目标验证方法:
pocsuite -r [poc_name] -u [target]
```
```
多目标:
pocsuite -r [poc_name] -f [files]
```
```
从fofa、zoomeye、shodan、鹰图获取目标
pocsuite -r [poc_name] --dork ['搜索语法'] --max-page [page] -o [output]
```
pocsuite 控制台参数说明

使用命令 poc-console 进去交互式控制台后，可通过 help 命令查看帮助，list 或 show all 列出所有 PoC 模块，use 加载某指定模块。相关参数可通过 set / setg 命令设置。

如下：
![image](https://user-images.githubusercontent.com/89974691/235065040-25db5c61-1f82-4276-a5be-f1294eac6b8c.png)

值得一提的是，在控制台中也可以执行系统命令。

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

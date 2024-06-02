# fscanOutput

### 一个用于处理fsacn输出结果的小脚本（尤其面对大量资产的fscan扫描结果做输出优化，**让你打点快人一步！！！**）

`python3 fscanOutput.py result.txt`

## 关于更新V2.3.1版本

1、优化密码提取规则，兼容新版本fscan！！！

## 关于更新V2.3版本

1、对各个模块进行优化，兼容了新版本的fscan；

2、新增NetInfo信息提取模块，包含NetBIOS信息；

3、新增各个模块txt格式输出，方便无Office环境、Linux命令行类型环境查看；

4、修复了一些BUG!

![image](https://github.com/ZororoZ/fscanOutput/assets/46238787/d5a3b48e-4816-49ef-bc64-1605859c6d34)


## 关于更新V2.2版本

1、优化弱口令模块，新增对应开放端口号，剔除多余显示的redis可写目录。

2、修复了一些BUG!

## 关于更新V2.1版本

1、新增txt文件编码修复功能；

2、新增存活IP段的功能；

3、修复一些已知的bug，优化弱口令的输出；

4、优化漏洞模块的输出。


## 关于更新V2.0版本

1、对工具进行了一些优化，修复了一些Bug。

2、对处理结果做了简单的输出。**更快！更高！更强！！！**

![image](https://user-images.githubusercontent.com/46238787/197140508-617a9758-837e-4350-bf99-7027f6e717db.png)

## 关于更新V1.03版本

1、由于fscan导出的个别结果中存在如下特殊字符，导致运行报错。
![图片](https://user-images.githubusercontent.com/46238787/181872469-af304c06-321d-4096-b211-0f995d8c0ed4.png)

2、整改了输出文件命名方式，与导入文件名称相同，方便查找。
![图片](https://user-images.githubusercontent.com/46238787/181872698-4d47653d-cd6f-4d52-a615-f9fed4b45987.png)


## 关于更新 V1.02 版本

1、将漏洞列表分为exp和poc;

2、将之前无法匹配的一些结果优化匹配；

![图片](https://user-images.githubusercontent.com/46238787/174651191-2f3d0fbf-2358-40b9-9bbc-047beb27e0a9.png)

![图片](https://user-images.githubusercontent.com/46238787/174651252-22edc59f-3b87-48cc-9fde-6dcabf343568.png)


## 使用方法

1、python3 fscanOutput.py result.txt

![图片](https://user-images.githubusercontent.com/46238787/174651780-484454d7-25e6-4fc2-a3db-ac0fbd07a6af.png)


2、输出结果为xlsx格式的文件，比较清楚的整理了fscan的各类型输出结果：

![图片](https://user-images.githubusercontent.com/46238787/160351612-00308a30-2241-4924-988c-8b9f063f9d76.png)

**注：为了最佳使用效果，请使用新版本fsan工具生成的结果进行处理**

sma11New师傅 YYDS

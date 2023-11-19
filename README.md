# clash_ini2sing-box
This project aims to migrate from the clash configuration file to the sing-box configuration file

## 2023-11-19更新
https://suburl.v1.mk/ 已经支持singbox转换
本项目仅为过渡时期使用，现在市面上出现了集成的转换产品，故不再更新

## 项目期许
基于clash配置文件，将clash的分流规则，原汁原味地转换为sing-box的分流规则

## 使用方法
1. 下载源代码
2. 将ini文件替换为自用的配置文件（也可不做更改）
3. 对template.json做自定义修改
   - 这里默认clash api端口为10000，如有更改请自行修改
4. 复制生成的config.json模板到 [sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe) 项目目录中当做模板使用

## 最终效果
![](https://github.com/izumiChan16/clash_ini2sing-box/raw/master/doc/2023-11-05%20103931.png)
![](https://github.com/izumiChan16/clash_ini2sing-box/raw/master/doc/2023-11-05%20104003.png)

## BUG
1. ~~分流后的规则堪堪可用，问题集中在list解析的顺序，在本项目中粗暴地将同一outbound的规则统一到一起，导致分流顺序出了问题。
   方案：每一条list按顺序解析为单独一个rule，而不是合并在一起~~（已修复）

## 有待完善
1. 本项目目前并未覆盖到所有的配置文件情况，仅覆盖大部分用户的使用情况，如有需要请自行修改代码。
2. 由于本人水平有限，代码写得很烂，如有更好的实现方法，欢迎PR
3. 由于本人时间有限，目前仅支持本地文件转换，如有需要通过配置链接在线生成，请自行修改代码

欢迎issue，也欢迎PR

## 感谢
[Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe)

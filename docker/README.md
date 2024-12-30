<p align="center">
  <a href="/docker/README_EN.md">English</a>
  ·
  <a href="/docker/README.md">简体中文</a>
</p>

## 为什么要使用脚本生成dockerfile

本项目分为多种语言，不同语言内容可能存在差异，为了减少维护成本 ，使用脚本生成dockerfile，方便后续维护。

## 使用方法

*生成dockerfile和docker-compose.yml*

``` shell
cd docker
python docker_tools.py -l CN
```

> 执行结束后会生成命令，按照指引运行即可
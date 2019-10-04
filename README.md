# android native anti hook
#### 0 project.zip为完整AS工程
#### 1 anti_hook.h .cpp为API函数原型
#### 2 conf.h的CONF结构为API输入原型，需要通过编写额外工具构造。
#### 3 native-lib.cpp为构造模拟数据，调用API的示例

#### 4 got.cpp为GOT_HOOK检测部分
#### 5 func.cpp为INLINE_HOOK检测部分
#### 6 sec.cpp为区段修改注入HOOK检测部分
#### 7 sys.cpp为系统库HOOK的检测部分

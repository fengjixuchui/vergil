#pragma once
#include <stdint.h>
typedef struct ANTI_HOOK{
    uint32_t global_data[48000];
}ANTI_HOOK;

extern "C" bool anti_hook(
        ANTI_HOOK* global,   // anti_hook的参数
        bool is_close,       // 调用完是否关闭初始化的资源
        uint32_t* arr_func,  // 要检测的函数地址(数组)
        uint32_t count);     // 数组元素个数




/*
输入：
1 所有SO库
2





 * */
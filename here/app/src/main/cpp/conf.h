#pragma once
#include "base.h"
#define FAIL_EXIT          exit(0);
#define CONF_ELE_COUNT     1024
#define CONF_ELE_BUFSZ     64
#define STR_KEY            0x44
#define STR_UTILS_IS_DEBUG false
#define IS_HOOK            1

enum class SEC_TYPE{
    TYPE_NULL = 0,
    TYPE_DYNSYM = 101,
    TYPE_DYNSTR = 102,
    TYPE_HASH = 103,
    TYPE_RELDYN = 104,
    TYPE_RELPLT = 105,
    TYPE_PLT = 106,
    TYPE_ARMEXTAB = 107,
    TYPE_ARMEXIDX = 108,
    TYPE_RODATA = 109,
    TYPE_FINIARRAY = 110,
    TYPE_INITARRAY = 111,
    TYPE_DYNAMIC = 112,
};

enum class CONF_TYPE{          // 字符串类型
    TYPE_NULL = 0,
    TYPE_STR = 1,              // 举例 "/proc/%d/maps" (一些普通的字符串)
    TYPE_LIB_NAME = 2,         // 举例 "libc.so" "libxxx.so" (库名)
    TYPE_GOT_ELE = 3,          // 举例 @@idx_gotitem##@@idx_libname##@@elfhash_symname##@@NULL## <多>
    TYPE_GOT_SEC = 4,          // 举例 @@head##@@end##@@NULL##@@NULL##(GOT表偏移)
    TYPE_FUNC_ELE = 5,         // 举例 @@idx_libname##@@head##@@end##@@hash##(函数信息)  <多> //
    TYPE_SEC_ELE = 6,          // 举例 @@type##@@head##@@end##@@filehash##(段信息)
    TYPE_SYSLIB_PATH = 7,      // 举例 "/system/lib/libc.so"或"/system/lib/liblog.so" (系统库路径)
    TYPE_SYS_ELE = 8,          // 举例 @@md_path##@@md_name##@@sym_name_hash##@@NULL##  <多>
    //TYPE_HOOK_FRAME,         // 举例 ~~~ (HOOK框架特征串)
};

STRUCT CONF_ELE{
    u32 type;
    char buf[CONF_ELE_BUFSZ];
}CONF_ELE;

typedef struct CONF{
    //u32 flag;
    u32 count;
    u32 idx_procpidmaps;
    u32 idx_libname_libcso;
    u32 idx_libname_self;
    u32 gottab_hash;
    u32 obj;
    u8 padding[8];
    CONF_ELE ele[CONF_ELE_COUNT];
}CONF;

// 0 mdbase
// 1 got
// 2 func
// 3 sec
// 4 sys
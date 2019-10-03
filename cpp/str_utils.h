#pragma once
#include "base.h"
#include "mem.h"
#include "conf.h"

namespace tokza{
    class STR_UTILS{
    public:
        STR_UTILS();
        ~STR_UTILS();
    public:
        u32 elfhash(char* input);                            // ELF哈希(字符串类型的都用这个)
        u32 membkdrhash(u32 base,u32 head,u32 end);          // BKDR哈希(内存类型的都用这个)
        u32 membkdrhash_half(u32 base,u32 head,u32 end);     // BKDR内存哈希(每2个字节计算1个字节)
        char* decstr(char* input,bool is_debug);             // 加解密字符串
        char* num2str(u32 num,bool is_hex);                  // 数字转字符
        u32   str2num(char* input);                          // 字符转数字
        char* get_encconf_by_idx(CONF* conf,u32 index);      // CONF INDEX--->加密的字符串
        char* get_decconf_by_idx(CONF* conf,u32 index);      // CONF IDNEX--->解密的字符串
        u32 get_confelfhash_by_idx(CONF* conf,u32 index);    // CONF IDNEX--->解密的字符串--->ELFHASH
        char* setpart(char* a,char* b,char* c,char* d);      // 构造组合字符串，只用于测试
        char* getpart(char* input,u32 part_num);             // 失败返回NULL，解构组合
        void su_close();
    private:
        MEM mem;
    };
}


/*
 * OK!
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 5;
    conf.idx_procpidmaps = 0;
    conf.idx_libname_libcso = 1;
    conf.idx_libname_self = 4;
    STR_UTILS su;
    DEBUG__set_fake_data_ele(&conf,0, su.decstr((char*)"/proc/%d/maps",STR_UTILS_IS_DEBUG), (u32)CONF_TYPE::TYPE_STR);
    DEBUG__set_fake_data_ele(&conf,1, su.decstr((char*)"libc.so",STR_UTILS_IS_DEBUG),       (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,2, su.decstr((char*)"liblog.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,3, su.decstr((char*)"libsm4.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,4, su.decstr((char*)"libape.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);

    // 加密CONF
    DEBUG__set_encrypt_global_conf(&conf);

    // 解密CONF
    CONFHANDLE confhandle(&conf);
    CONF* dec_conf = confhandle.get();

    // ...
    STR_UTILS str_utils;
    u32 hash = str_utils.elfhash((char*)"12345");

    u8 buf[] = {1,2,3,4,5,6,7,8,9};
    u32 hash1 = str_utils.membkdrhash(0,(u32)buf,(u32)buf + sizeof(buf));
    u32 hash2 =  str_utils.membkdrhash_half(0,(u32)buf,(u32)buf + sizeof(buf));

    char* dec1 = str_utils.decstr((char*)"1234567", false);
    char* dec2 = str_utils.decstr((char*)"1234567", true);

    char* str1 = str_utils.num2str(0x123,true);
    u32 num1 = str_utils.str2num((char*)"123");

    char* enc_a = str_utils.get_encconf_by_idx(dec_conf,1);
    char* enc_b = str_utils.get_encconf_by_idx(dec_conf,2);
    char* enc_c = str_utils.get_encconf_by_idx(dec_conf,3);

    char* dec_a = str_utils.get_decconf_by_idx(dec_conf,1);
    char* dec_b = str_utils.get_decconf_by_idx(dec_conf,2);
    char* dec_c = str_utils.get_decconf_by_idx(dec_conf,3);

    u32 hash_a = str_utils.get_confelfhash_by_idx(dec_conf,1);
    u32 hash_b = str_utils.get_confelfhash_by_idx(dec_conf,2);
    u32 hash_c = str_utils.get_confelfhash_by_idx(dec_conf,3);

    char* part = str_utils.setpart((char*)"11",(char*)"22",(char*)"33",(char*)"44");
    char* p1 = str_utils.getpart(part,1);
    char* p2 = str_utils.getpart(part,2);
    char* p3 = str_utils.getpart(part,3);
    char* p4 = str_utils.getpart(part,4);
 */
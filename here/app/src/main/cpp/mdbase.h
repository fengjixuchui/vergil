#pragma once
#include "base.h"
#include "utils.h"
#include "confhandle.h"

namespace tokza{
    STRUCT MD_INFO{
        u32 index;                    // conf index
        u32 hash;                     // elfhash_md_name
        u32 md_base;                  // 基址
    }MD_INFO;

    class MDBASE{
    public:
        MDBASE(CONFHANDLE& confhandle__);
        ~MDBASE();
        u32 getbyhash(u32 hash);      // 失败时返回0
        u32 getbyidx(u32 idx);        // 失败时返回0
        u32 get_libc();               // 失败时返回0
        u32 get_self();               // 失败时返回0
    private:
        bool init();
        MD_INFO* sub_init(u32 idx);
    private:
        bool flag;                    // ...
        CONF* dec_conf;               // 解密后的conf
        UTILS utils;                  // ...
        STR_UTILS str_utils;          // ...
        CONFHANDLE& confhandle;       // ...
        map<u32,MD_INFO*> hash_key;   // map<elfhashmd_name,***>
        map<u32,MD_INFO*> idx_key;    // map<conf_index,***>
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
    CONF* dec_conf = confhandle.get_dec_conf();

    // ...
    MDBASE mdbase(confhandle);
    u32 base_self = mdbase.get_self();
    u32 base_libc = mdbase.get_libc();

    u32 base1 = mdbase.getbyidx(1);
    u32 base2 = mdbase.getbyidx(2);
    u32 base3 = mdbase.getbyidx(3);
    u32 base4 = mdbase.getbyidx(4);

    u32 base11 = mdbase.getbyhash(su.get_confelfhash_by_idx(dec_conf,1));
    u32 base22 = mdbase.getbyhash(su.get_confelfhash_by_idx(dec_conf,2));
    u32 base33 = mdbase.getbyhash(su.get_confelfhash_by_idx(dec_conf,3));
    u32 base44 = mdbase.getbyhash(su.get_confelfhash_by_idx(dec_conf,4));
 */
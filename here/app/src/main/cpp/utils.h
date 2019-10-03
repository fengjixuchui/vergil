#pragma once
#include "base.h"
#include "str_utils.h"

namespace tokza{
    class UTILS {
    public:
        UTILS();
        ~UTILS();
    public:
        u32 find_mdbase_by_maps(char* enc_mdname,char* enc_procpidmaps);                  // 失败时返回0、获取模块基址
        bool my_dlsym(u32 mdbase, u32 elfhash_name,u32* output_addr,u32 *output_sz);      // 失败时返回false、内存中符号查找(输出为后两个参数)
        u32 get_filesz(char* enc_path);                                                   // 失败时返回0、获取文件大小
        bool readfile_tomem(char* enc_path, u8* buf, u32 size);                           // 失败时返回false、将文件读入内存
        bool file_dlsym(u32 buf_base, u32 elfhash_name,u32* output_addr,u32* output_sz);  // 失败时返回false、文件中符号查找
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
    // find_mdbase_by_maps
    tokza::UTILS utils;
    u32 mdbase1 = utils.find_mdbase_by_maps( su.decstr((char*)"libc.so",STR_UTILS_IS_DEBUG),su.decstr((char*)"proc/%d/maps",STR_UTILS_IS_DEBUG));
    u32 mdbase2 = utils.find_mdbase_by_maps(su.decstr((char*)"libcxxx.so",STR_UTILS_IS_DEBUG),su.decstr((char*)"proc/%d/maps",STR_UTILS_IS_DEBUG));

    // my_dlsym
    STR_UTILS str_utils;
    u32 elfhashval = str_utils.elfhash((char*)"fopen");
    u32 output_addr = 0;
    u32 output_sz = 0;
    bool ret = utils.my_dlsym(mdbase1,elfhashval,&output_addr,&output_sz);

    // get_filesz、readfile_tomem、file_dlsym
    MEM mem;
    u32 output_addr2 = 0;u32 output_sz2 = 0;
    u32 size = utils.get_filesz(su.decstr((char*)"/system/lib/libc.so",STR_UTILS_IS_DEBUG));
    u8* buf = (u8*)mem.get(size);
    ret = utils.readfile_tomem( su.decstr((char*)"/system/lib/libc.so",STR_UTILS_IS_DEBUG), buf, size);
    ret = utils.file_dlsym((u32)buf,elfhashval,&output_addr2,&output_sz2);
    */
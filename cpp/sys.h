#pragma once
#include "base.h"
#include "confhandle.h"
#include "mdbase.h"

namespace tokza{
    STRUCT SYS_ELE{
        // 举例 @@md_path##@@md_name##@@sym_name_hash##@@NULL##
        SYS_ELE();
        ~SYS_ELE();
        u32 md_path;                // 库路径（下标）（预设）
        u32 md_name;                // 库名(下标)（预设）
        u32 sym_name;               // 符号名(ELF_HASH)（预设）

        u8* buf;                    // 首地址(运行实时计算)
        u32 md_base;                // 模块基址(运行实时计算)

        u32 fhead;                  // 偏移/虚拟地址(运行实时计算)
        u32 fend;                   // 偏移/虚拟地址(运行实时计算)
        u32 fhash;                  // HASH(运行实时计算)

        u32 mhead;                  // 偏移/虚拟地址(运行实时计算)
        u32 mend;                   // 偏移/虚拟地址(运行实时计算)
        u32 mhash;                  // HASH(运行实时计算)
    }SYS_ELE;

    class SYS{
    public:
        SYS(CONFHANDLE& confhandle__,MDBASE& mdbase__);
        ~SYS();
    public:
        bool check();
    private:
        bool init();
        u8* sub_init_syslib(u32 idx);
        SYS_ELE* sub_init_sysele(u32 idx);
        void get_hash();
    private:
        bool flag;
        u32 is_hook;
        map<u32,u8*> msyslib;       // map<idx,buf>
        map<u32,SYS_ELE*> msysele;  // map<sym_name_elfhash,buf>
    private:
        MEM mem;
        UTILS utils;
        CONF* dec_conf;
        CONFHANDLE& confhandle;
        MDBASE& mdbase;
    };
}


/*
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 18;
    conf.idx_procpidmaps = 0;
    conf.idx_libname_libcso = 1;
    conf.idx_libname_self = 4;
    MEM mem;
    STR_UTILS su;
    UTILS utils;
    DEBUG__set_fake_data_ele(&conf,0, su.decstr((char*)"/proc/%d/maps",STR_UTILS_IS_DEBUG), (u32)CONF_TYPE::TYPE_STR);
    DEBUG__set_fake_data_ele(&conf,1, su.decstr((char*)"libc.so",STR_UTILS_IS_DEBUG),       (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,2, su.decstr((char*)"liblog.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,3, su.decstr((char*)"libsm4.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);
    DEBUG__set_fake_data_ele(&conf,4, su.decstr((char*)"libape.so",STR_UTILS_IS_DEBUG),     (u32)CONF_TYPE::TYPE_LIB_NAME);

    // 构造模拟数据
    // @@idx_gotitem##@@idx_libname##@@elfhash_symname##@@NULL##
    conf.gottab_hash = 0;
    char* temp_str1 = su.setpart((char*)"38",(char*)"1",su.num2str( su.elfhash((char*)"malloc"),false ),(char*)"NULL");
    char* temp_str2 = su.setpart((char*)"58",(char*)"1",su.num2str( su.elfhash((char*)"free"),false ),(char*)"NULL");
    char* temp_str3 = su.setpart((char*)"37",(char*)"2",su.num2str( su.elfhash((char*)"__android_log_print"),false ),(char*)"NULL");
    char* temp_str4 = su.setpart((char*)"0x23EB8",(char*)"0x23FFC",(char*)"NULL",(char*)"NULL");
    DEBUG__set_fake_data_ele(&conf,5,su.decstr(temp_str1,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_GOT_ELE);
    DEBUG__set_fake_data_ele(&conf,6,su.decstr(temp_str2,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_GOT_ELE);
    DEBUG__set_fake_data_ele(&conf,7,su.decstr(temp_str3,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_GOT_ELE);
    DEBUG__set_fake_data_ele(&conf,8,su.decstr(temp_str4,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_GOT_SEC);


    // 构造模拟数据
    // @@idx_libname##@@head##@@end##@@hash##
    u32 libsz = utils.get_filesz(su.decstr((char*)"/data/data/com.example.vergil3/lib/libape.so",STR_UTILS_IS_DEBUG));
    u8* buf = (u8*)(mem.get(libsz));
    bool ret = utils.readfile_tomem(su.decstr((char*)"/data/data/com.example.vergil3/lib/libape.so",STR_UTILS_IS_DEBUG),buf,libsz);
    char* func_str1 = su.setpart((char*)"4",(char*)"0x46A8",(char*)"0x47EC",su.num2str(su.membkdrhash_half((u32)buf,0x46A8,0x47EC),false)  );
    char* func_str2 = su.setpart((char*)"4",(char*)"0x4800",(char*)"0x4968",su.num2str(su.membkdrhash_half((u32)buf,0x4800,0x4968),false)  );
    char* func_str3 = su.setpart((char*)"4",(char*)"0x4978",(char*)"0x4AB0",su.num2str(su.membkdrhash_half((u32)buf,0x4978,0x4AB0),false)  );
    DEBUG__set_fake_data_ele(&conf,9,su.decstr(func_str1,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_FUNC_ELE);
    DEBUG__set_fake_data_ele(&conf,10,su.decstr(func_str2,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_FUNC_ELE);
    DEBUG__set_fake_data_ele(&conf,11,su.decstr(func_str3,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_FUNC_ELE);

    // 构造模拟数据
    // @@md_path##@@md_name##@@sym_name_hash##@@NULL##
    // TYPE_LIB_NAME,    // 举例 "libc.so" "libxxx.so" (库名)
    // TYPE_SYSLIB_PATH, // 举例 "/system/lib/libc.so"或"/system/lib/liblog.so" (系统库路径)
    // TYPE_SYS_ELE,     // 举例 @@md_path##@@md_name##@@sym_name_hash##@@NULL##
    DEBUG__set_fake_data_ele(&conf,12, su.decstr((char*)"/system/lib/libc.so",STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYSLIB_PATH);
    DEBUG__set_fake_data_ele(&conf,13, su.decstr((char*)"/system/lib/liblog.so",STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYSLIB_PATH);

    char* sys1 = su.setpart("12","1",su.num2str( su.elfhash((char*)"fopen"),false ),              "NULL");
    char* sys2 = su.setpart("12","1",su.num2str( su.elfhash((char*)"mprotect"),false ),           "NULL");
    char* sys3 = su.setpart("12","1",su.num2str( su.elfhash((char*)"ptrace"),false ),             "NULL");
    char* sys4 = su.setpart("13","2",su.num2str( su.elfhash((char*)"__android_log_print"),false ),"NULL");

    DEBUG__set_fake_data_ele(&conf,14,su.decstr(sys1,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,15,su.decstr(sys2,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,16,su.decstr(sys3,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,17,su.decstr(sys4,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);

    // 加密CONF
    DEBUG__set_encrypt_global_conf(&conf);

    // 创建CONFHANDLE
    CONFHANDLE confhandle(&conf);
    MDBASE mdbase(confhandle);

    // 测试SYS
    //  SYS(CONFHANDLE& confhandle__,MDBASE& mdbase__);
    SYS sys(confhandle,mdbase);
    ret = sys.check();
    ret = sys.check();
    ret = sys.check();

*/
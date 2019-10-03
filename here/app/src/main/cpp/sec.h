#pragma once
#include "base.h"
#include "confhandle.h"
#include "mdbase.h"

namespace tokza{
    STRUCT SEC_ELE{
        SEC_ELE();
        ~SEC_ELE();
        u32 head;                 // 起始偏移（预设）
        u32 end;                  // 结束偏移（预设）
        u32 file_hash;            // 文件时的HASH（预设）
        u32 mem_hash;             // 运行时内存HASH（运行实时计算）
    }SEC_ELE;

    class SEC{
    public:
        SEC(CONFHANDLE& confhandle__,MDBASE& mdbase__);
        ~SEC();
        bool check();
    private:
         bool init();
         void sub_init(SEC_ELE& ele,u32 head,u32 end,u32 file_hash);
         void get_memhash();
         void sub_getmemhash(SEC_ELE& ele,u32 base);
         void sub_getmemhashload2(SEC_ELE& ele,u32 base);
    private:
        struct {
            SEC_ELE dynsym;
            SEC_ELE dynstr;
            SEC_ELE hash;
            SEC_ELE reldyn;
            SEC_ELE relplt;
            SEC_ELE plt;
            SEC_ELE arm_extab;
            SEC_ELE arm_exidx;
            SEC_ELE rodata;
        }LOAD1;
        struct {
            SEC_ELE fini_array;
            SEC_ELE init_array;
            SEC_ELE dynamic;
        }LOAD2;
        bool flag;
        u32 is_hook;
    private:
        STR_UTILS str_utils;        // ...
        MDBASE& mdbase;             // 基址信息
        CONFHANDLE& confhandle;     // ...
        CONF* dec_conf;             // 配置文件
    };
}


/*
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 24;
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
    // 举例 @@type##@@head##@@end##@@filehash##(段信息)
    char* secele_dynsym =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_DYNSYM,false),
            (char*)"276",
            (char*)"5236",
            su.num2str(su.membkdrhash_half((u32)buf,276,5236),false)  );

    char* secele_dynstr =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_DYNSTR,false),
            (char*)"5236",
            (char*)"9248",
            su.num2str(su.membkdrhash_half((u32)buf,5236,9248),false)  );

    char* secele_hash =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_HASH,false),
            (char*)"9248",
            (char*)"11548",
            su.num2str(su.membkdrhash_half((u32)buf,9248,11548),false)  );

    char* secele_rel_dyn =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_RELDYN,false),
            (char*)"11548",
            (char*)"17132",
            su.num2str(su.membkdrhash_half((u32)buf,11548,17132),false)  );

    char* secele_rel_plt =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_RELPLT,false),
            (char*)"17132",
            (char*)"17500",
            su.num2str(su.membkdrhash_half((u32)buf,17132,17500),false)  );

    char* secele_plt =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_PLT,false),
            (char*)"17500",
            (char*)"18072",
            su.num2str(su.membkdrhash_half((u32)buf,17500,18072),false)  );

    char* secele_ARM_extab =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_ARMEXTAB,false),
            (char*)"120528",
            (char*)"124480",
            su.num2str(su.membkdrhash_half((u32)buf,120528,124480),false)  );

    char* secele_ARM_exidx =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_ARMEXIDX,false),
            (char*)"124480",
            (char*)"126680",
            su.num2str(su.membkdrhash_half((u32)buf,124480,126680),false)  );

    char* secele_rodata =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_RODATA,false),
            (char*)"126680",
            (char*)"139668",
            su.num2str(su.membkdrhash_half((u32)buf,126680,139668),false)  );

    char* secele_fini_array =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_FINIARRAY,false),
            (char*)"144280",
            (char*)"144288",
            su.num2str(su.membkdrhash_half((u32)buf,140184,140192),false)  ); // .fini_array     144280     144288     140184     140192   NO

    char* secele_init_array =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_INITARRAY,false),
            (char*)"146860",
            (char*)"146868",
            su.num2str(su.membkdrhash_half((u32)buf,142764,142772),false)  ); // .init_array     146860     146868     142764     142772   NO

    char* secele_dynamic =su.setpart(
            su.num2str((u32)SEC_TYPE::TYPE_DYNAMIC,false),
            (char*)"146868",
            (char*)"147124",
            su.num2str(su.membkdrhash_half((u32)buf,142772,143028),false)  ); // .dynamic     146868     147124     142772     143028   NO

    DEBUG__set_fake_data_ele(&conf,12, su.decstr(secele_dynsym,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,13, su.decstr(secele_dynstr,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,14, su.decstr(secele_hash,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,15, su.decstr(secele_rel_dyn,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,16, su.decstr(secele_rel_plt,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,17, su.decstr(secele_plt,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,18, su.decstr(secele_ARM_extab,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,19, su.decstr(secele_ARM_exidx ,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,20, su.decstr(secele_rodata,STR_UTILS_IS_DEBUG) ,(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,21, su.decstr(secele_fini_array,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,22, su.decstr(secele_init_array,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SEC_ELE);
    DEBUG__set_fake_data_ele(&conf,23, su.decstr(secele_dynamic,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SEC_ELE);

    // 加密CONF
    DEBUG__set_encrypt_global_conf(&conf);

    // 创建CONFHANDLE
    CONFHANDLE confhandle(&conf);
    MDBASE mdbase(confhandle);

    // 测试SEC
    SEC sec(confhandle,mdbase);
    ret = sec.check();
    ret = sec.check();
    ret = sec.check();
 */
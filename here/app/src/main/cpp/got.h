#pragma once
#include "base.h"
#include "mdbase.h"
#include "confhandle.h"

namespace tokza{
    STRUCT GOT_ELE{
        // @@idx_gotitem##@@idx_libname##@@elfhash_symname##@@NULL##
        GOT_ELE();
        ~GOT_ELE();
        u32 idx_gotitem;            // GOT项下标（预设）
        u32 idx_libname;            // GOT项所属模块（下标）（预设）
        u32 elfhash_symname;        // GOT项符号名（ELFHASH）（预设）
        u32 gotitem;                // GOT项内容（运行实时计算）
        u32 sym_addr;               // 手动解析获取的符号虚拟地址（运行实时计算）
    }GOT_ELE;

    class GOT {
    public:
        GOT(CONFHANDLE& confhandle__,MDBASE& mdbase__);
        ~GOT();
        bool check();               // 检测到HOOK返回true
    private:
        bool initsec();             // 错误时返回false
        bool initmap();             // 错误时返回false
        GOT_ELE* getele(u32 idx);   // 错误时返回nullptr
        u32 getgotitem(GOT_ELE* p); // 错误时返回0
        u32 getsymaddr(GOT_ELE* p); // 错误时返回0
        bool gethash();             // 错误时返回false
    private:
        bool flag;
        u32 is_hook;                // 检测结果（运行实时计算）
        u32 head;                   // GOT表起始偏移（预设）@@head##@@end##@@NULL##@@NULL##
        u32 end;                    // GOT表结束偏移（预设）
        u32 hash;                   // GOT表hash（运行实时计算）
        map<u32,GOT_ELE*> m;        // map<elfhash_name,GOT_ELE*>
    private:
        MDBASE& mdbase;             // 基址信息
        CONF* dec_conf;             // 配置文件
        CONFHANDLE& confhandle;     // ...
    };
}

/*
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 9;
    conf.idx_procpidmaps = 0;
    conf.idx_libname_libcso = 1;
    conf.idx_libname_self = 4;
    STR_UTILS su;
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

    // 加密CONF
    DEBUG__set_encrypt_global_conf(&conf);

    // 解密CONF
    CONFHANDLE confhandle(&conf);
    CONF* dec_conf = confhandle.get_dec_conf();


    // 测试GOT接口
    MDBASE mdbase(confhandle);
    GOT& got = *(new GOT(confhandle,mdbase));
    bool ret = got.check();                  // 情况0
    ret = got.check();                       // 情况1
    ret = got.check();                       // 情况1
    delete &got;

    GOT& got2 = *(new GOT(confhandle,mdbase));
    bool ret2 = got2.check();;                // 情况2
    ret2 = got2.check();                      // 情况1
    ret2 = got2.check();                      // 情况1
    delete &got2;

    // 保存
    confhandle.save();

*/
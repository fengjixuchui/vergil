#pragma once
#include "conf.h"
#include "mdbase.h"

namespace tokza{
    STRUCT FUNC_ELE{
        // @@idx_libname##@@head##@@end##@@hash##
        FUNC_ELE();
        ~FUNC_ELE();
        u32 idx_libname;                          // 所属模块名（预设）
        u32 head;                                 // 函数起始偏移（预设）（该设定,THUMB指令时,必须为偶数地址）
        u32 end;                                  // 函数结束偏移（预设）
        u32 filehash;                             // 函数哈希（预设）
        u32 md_base;                              // 所属模块基址（运行时计算）
        u32 addr;                                 // 函数地址（运行时计算）
    }FUNC_ELE;

    class FUNC{
    public:
        FUNC(CONFHANDLE& confhandle__,MDBASE& mdbase__);
        ~FUNC();
        bool check(u32* arr_func_addr,u32 count); // 检测到HOOK返回true、参数为1函数地址数组、2数组长度（注意输入的函数地址可以为奇，但class内部处理以偶数为准）
    private:
        bool check_single(u32 func_addr);         // 检测到HOOK返回true、即时演算函数hash与预设函数hash进行对比
        bool initmap();                           // 错误时返回false、  初始化数据结构
        FUNC_ELE* getele(u32 idx);                // 错误时返回nullptr、初始化数据结构
    private:
        bool flag;                                // ...
        map<u32,FUNC_ELE*> m;                     // map<函数虚拟地址,函数信息结构*>
    private:
        MDBASE& mdbase;                           // 基址信息
        CONFHANDLE& confhandle;                   // ...
        CONF* dec_conf;                           // 配置文件
        STR_UTILS str_utils;                      // 字符串处理工具类
    };
}


/*
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 12;
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

    // 加密CONF
    DEBUG__set_encrypt_global_conf(&conf);

    // 创建CONFHANDLE
    CONFHANDLE confhandle(&conf);
    MDBASE mdbase(confhandle);

    // 测试FUNC
    void* handle = dlopen((char*)"/data/data/com.example.vergil3/lib/libape.so",RTLD_LAZY);
    u32 arr[3] = {0};;
    arr[0] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nIsApeFormat");
    arr[1] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nInitApeLib");
    arr[2] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nCleanupApeLib");
    FUNC func(confhandle,mdbase);
    bool ret1 = func.check(arr,3);
    bool ret2 = func.check(arr,3);
    bool ret3 = func.check(arr,3);
*/
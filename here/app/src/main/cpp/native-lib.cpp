#include <jni.h>
#include <string>
#include <map>

#include "mem.h"
#include "str_utils.h"
#include "utils.h"
#include "sm4.h"
//#include "mdbase.h"
//#include "got.h"
//#include "func.h"
//#include "confhandle.h"
//#include "sec.h"
//#include "sys.h"
#include "anti_hook.h"

using namespace std;
using namespace tokza;

void DEBUG__set_fake_data_ele(CONF* conf,u32 index,char* str,u32 type){
    conf->ele[index].type = type;
    memcpy(conf->ele[index].buf,str,strlen(str));
    return;
}

void DEBUG__set_encrypt_global_conf(CONF* conf){
    if( 0!=sizeof(CONF)%16 ){
        LOGD("NEED :%d.\n",16- sizeof(CONF)%16);
        return;
    }else{
        u8 key[16] = {0};
        SM4 sm4;
        SM4INFO* sm4info = sm4.enc((u8*)(conf),sizeof(CONF),key);
        memset(conf,0,sizeof(CONF));
        memcpy(conf,sm4info->output,sizeof(CONF));
        return;
    }
}

void DEBUG_set_save_global_conf(CONF* old_conf,CONF* new_conf){
    memset(old_conf,0,sizeof(CONF));
    memcpy(old_conf,new_conf,sizeof(CONF));
    DEBUG__set_encrypt_global_conf(old_conf);
    return;
}


extern "C" JNIEXPORT jstring JNICALL Java_com_example_vergil3_MainActivity_stringFromJNI(JNIEnv* env, jobject /* this */) {
    // 构造模拟数据
    CONF conf = {0};
    conf.count = 30;
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


    // 构造模拟数据
    // @@md_path##@@md_name##@@sym_name_hash##@@NULL##
    // TYPE_LIB_NAME,    // 举例 "libc.so" "libxxx.so" (库名)
    // TYPE_SYSLIB_PATH, // 举例 "/system/lib/libc.so"或"/system/lib/liblog.so" (系统库路径)
    // TYPE_SYS_ELE,     // 举例 @@md_path##@@md_name##@@sym_name_hash##@@NULL##
    DEBUG__set_fake_data_ele(&conf,24, su.decstr((char*)"/system/lib/libc.so",STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYSLIB_PATH);
    DEBUG__set_fake_data_ele(&conf,25, su.decstr((char*)"/system/lib/liblog.so",STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYSLIB_PATH);

    char* sys1 = su.setpart((char*)"24",(char*)"1",su.num2str( su.elfhash((char*)"fopen"),false ),              "NULL");
    char* sys2 = su.setpart((char*)"24",(char*)"1",su.num2str( su.elfhash((char*)"mprotect"),false ),           "NULL");
    char* sys3 = su.setpart((char*)"24",(char*)"1",su.num2str( su.elfhash((char*)"ptrace"),false ),             "NULL");
    char* sys4 = su.setpart((char*)"25",(char*)"2",su.num2str( su.elfhash((char*)"__android_log_print"),false ),"NULL");

    DEBUG__set_fake_data_ele(&conf,26,su.decstr(sys1,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,27,su.decstr(sys2,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,28,su.decstr(sys3,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);
    DEBUG__set_fake_data_ele(&conf,29,su.decstr(sys4,STR_UTILS_IS_DEBUG),(u32)CONF_TYPE::TYPE_SYS_ELE);

    // 加密CONF
    //DEBUG__set_encrypt_global_conf(&conf);
    void* handle = dlopen((char*)"/data/data/com.example.vergil3/lib/libape.so",RTLD_LAZY);
    u32 arr[3] = {0};
    arr[0] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nIsApeFormat");
    arr[1] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nInitApeLib");
    arr[2] = (u32)dlsym(handle,"Java_com_tencent_qqmusic_mediaplayer_codec_ape_ApeDecoder_nCleanupApeLib");
    ret = anti_hook((ANTI_HOOK*)&conf,false,arr,3);
    ret = anti_hook((ANTI_HOOK*)&conf,false,arr,3);
    ret = anti_hook((ANTI_HOOK*)&conf,true,arr,3);
    ret = anti_hook((ANTI_HOOK*)&conf,true,arr,3);
    ret = anti_hook((ANTI_HOOK*)&conf,false,arr,3);


    std::string hello = "Hello from C++";return env->NewStringUTF(hello.c_str());
}

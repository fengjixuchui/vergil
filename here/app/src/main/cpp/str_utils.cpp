#include "str_utils.h"

namespace tokza{
    STR_UTILS::STR_UTILS() {
    }

    STR_UTILS::~STR_UTILS() {
        su_close();
    }

    u32 STR_UTILS::elfhash(char* input){
        char* s = input;
        u32 h = 0, g = 0;
        while(*s) {
            h = (h << 4) + *s++;
            g = h & 0xf0000000;
            h ^= g;
            h ^= g >> 24;
        }
        return h;
    }

    u32 STR_UTILS::membkdrhash(u32 base,u32 head,u32 end){
        // BKDRHash
        u32 ret = 0;
        u32 M = 249997;
        u32 seed = 131;
        u32 hash = 0;
        u8* a = NULL;
        u8* b = NULL;

        // 计算
        a = (u8*)(base + head);
        b = (u8*)(base + end);
        while(a<b) {
            hash = hash*seed + (*a);
            ++a;
        }
        ret = (u32)(hash % M);

        // 清理内存痕迹
        M = 0;
        seed = 0;
        hash = 0;
        a = NULL;
        b = NULL;
        base = 0;
        head = 0;
        end = 0;

        // 返回
        return ret;
    }

    u32 STR_UTILS::membkdrhash_half(u32 base,u32 head,u32 end){
        // BKDRHash
        u32 ret = 0;
        u32 M = 249997;
        u32 seed = 131;
        u32 hash = 0;
        u8* a = NULL;
        u8* b = NULL;

        // 计算
        a = (u8*)(base + head);
        b = (u8*)(base + end);
        while(a<b) {
            hash = hash*seed + (*a);
            a += 2;
        }
        ret = (u32)(hash % M);

        // 清理内存痕迹
        M = 0;
        seed = 0;
        hash = 0;
        a = NULL;
        b = NULL;
        base = 0;
        head = 0;
        end = 0;

        // 返回
        return ret;
    }

    char* STR_UTILS::decstr(char* input,bool is_debug){
        u32 len = strlen(input);
        char* buf = (char*)(mem.get(len+1));

        if(is_debug) {
            for(u32 k = 0; k < len; k++) {
                buf[k] = input[k];
            }//for
        }
        else {
            for(u32 k = 0; k < len; k++) {
                if( STR_KEY != input[k] && 0 != input[k] )
                    buf[k] = input[k] ^ STR_KEY;
                else
                    buf[k] = input[k];
            }//for
        }
        return buf;
    }

    char* STR_UTILS::num2str(u32 num,bool is_hex){
        char* buf = (char*)(mem.get(11));
        if( is_hex ) {
            snprintf(buf, 11, "0x%08x", num);
            return buf;
        }else {
            snprintf(buf,11,"%d",num);
            return buf;
        }
    }

    u32 STR_UTILS::str2num(char* input){
        return strtoul(input,NULL,0);
    }

    char* STR_UTILS::get_encconf_by_idx(CONF* conf,u32 index){
        char* enc = conf->ele[index].buf;
        return enc;
    }

    char* STR_UTILS::get_decconf_by_idx(CONF* conf,u32 index){
        char* enc = conf->ele[index].buf;
        char* dec = this->decstr(enc,STR_UTILS_IS_DEBUG);
        return dec;
    }

    u32 STR_UTILS::get_confelfhash_by_idx(CONF* conf,u32 index){
        char* enc = conf->ele[index].buf;
        char* dec = this->decstr(enc,STR_UTILS_IS_DEBUG);
        u32 hash = this->elfhash(dec);
        return hash;
    }

    char* STR_UTILS::setpart(char* a,char* b,char* c,char* d){
        u32 len = strlen(a) + strlen(b) + strlen(c) + strlen(d) + 4*strlen("@@##") + 1;
        char* buf = (char*)(mem.get(len));
        strcat(buf,"@@");strcat(buf,a);strcat(buf,"##");
        strcat(buf,"@@");strcat(buf,b);strcat(buf,"##");
        strcat(buf,"@@");strcat(buf,c);strcat(buf,"##");
        strcat(buf,"@@");strcat(buf,d);strcat(buf,"##");
        return buf;
    }

    char* STR_UTILS::getpart(char* input,u32 part_num){
        // 测试输入 char* p = __strtool_setpart__(strtool,"111","2","3333","44444");
        // @  @  1  1  1  #  #  @  @  2  #  #  @  @  3  3  3  3  #  #  @  @  4  4  4  4  4  #  #
        // 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28

        // check 1
        if( part_num<1 || part_num>4 ){
            LOGD("STR_UTILS::getpart(),fail.\n");
            return NULL;
        }

        // check 2
        char* t = input;
        for(u32 k =0; k<4; k++){
            char* ret = strstr(t,"@@");
            if(NULL==ret){
                LOGD("STR_UTILS::getpart(),fail.\n");
                return NULL;
            }else{
                t = ret + 2;
            }
        }

        // check 3
        t = input;
        for(u32 k =0; k<4; k++){
            char* ret = strstr(t,"##");
            if(NULL==ret){
                LOGD("STR_UTILS::getpart(),fail.\n");
                return NULL;
            }else{
                t = ret + 2;
            }
        }

        // index
        u32 head = 0;
        u32 end = 0;
        for(u32 k =0;k < part_num; k++){
            if(0==k){
                head = (u32)(strstr( input + head  , "@@") - input);
                end = (u32)(strstr( input + end  , "##") - input);
            }else{
                head = (u32)(strstr( input + head + 2 , "@@") - input);
                end = (u32)(strstr( input + end + 2 , "##") - input);
            }
        }

        // copy
        u32 len = end - head - 2 + 1;
        char* buf = (char*)( mem.get(len) );
        u32 acc = 0;
        for(u32 k =head+2; k<end; k++){
            buf[acc] = input[k];
            acc ++;
        }//for

        // ...
        return buf;
    }

    void STR_UTILS::su_close() {
        this->mem.close();
        return;
    }

}
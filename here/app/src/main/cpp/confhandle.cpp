#include "confhandle.h"
#include "str_utils.h"

namespace tokza{
    CONFHANDLE::CONFHANDLE(CONF* g_conf__) {
        this->g_conf = g_conf__;
        this->flag = false;
        this->dec_conf = nullptr;
    }

    CONFHANDLE::~CONFHANDLE() {
        this->flag = false;
        this->g_conf = nullptr;
        this->dec_conf = nullptr;
        mulmap.clear();
        return;
    }

    bool CONFHANDLE::init_conf(){
//        if( 0 != sizeof(CONF)%16 ){
//            LOGD("CONFHANDLE::init_conf(),fail.\n");
//            LOGD("NEED :%d.\n",16- sizeof(CONF)%16);
//            return false;
//        }else{
//            u8 key[16] = {0};
//            SM4INFO* sm4info = sm4.dec((u8*)(this->g_conf),sizeof(CONF),key);
//            this->dec_conf = (CONF*)(sm4info->output);
//            return true;
//        }

        /** 调试 省略SM4加密 **/
        if( 0 != sizeof(CONF)%16 ){
            LOGD("CONFHANDLE::init_conf(),fail.\n");
            LOGD("NEED :%d.\n",16- sizeof(CONF)%16);
            return false;
        }else{
            this->dec_conf = this->g_conf;
            return true;
        }
        /** 调试 省略SM4加密 **/
    }

    bool CONFHANDLE::init_map(){
        u32 count = this->dec_conf->count;
        CONF_ELE* arr = this->dec_conf->ele;

        // 创建mulmap<CONF_TYPE,idx>
        for(u32 k = 0; k < count; k++){
            this->mulmap.INSERT( (CONF_TYPE)(arr[k].type), k);
        }//for
        return true;
    }

    CONF* CONFHANDLE::get_dec_conf() {
        if(!this->flag){
            if(!init_conf() || !init_map()){
                LOGD("CONFHANDLE::get_dec_conf(),fail.\n");
                return nullptr;
            }
            this->flag = true;
        }
        return this->dec_conf;
    }

    multimap<CONF_TYPE, u32>* CONFHANDLE::get_map() {
        if(!this->flag){
            if(!init_conf() || !init_map()){
                LOGD("CONFHANDLE::get_map(),fail.\n");
                return nullptr;
            }
            this->flag = true;
        }
        return &(this->mulmap);
    }

    void CONFHANDLE::save(){
//        if(this->flag){
//            u8 key[16] = {0};
//            SM4INFO* sm4info = sm4.enc((u8*)(this->dec_conf),sizeof(CONF),key);
//            memset(this->g_conf,0,sizeof(CONF));
//            memcpy(this->g_conf,sm4info->output,sizeof(CONF));
//            return;
//        }//if

        /** 调试 省略SM4加密 **/
        return;
        /** 调试 省略SM4加密 **/
    }

    bool CONFHANDLE::get_type_vec(CONF_TYPE type, vector<u32> &vec) {
        vec.clear();
        auto it = mulmap.find(type);
        auto all= mulmap.count(type);
        if(0==all){
            return false;
        }else{
            for(u32 k = 0; k != all; k++,it++){
                u32 idx = it->second;
                vec.push_back(idx);
            }//for
            return true;
        }//if else
    }

}
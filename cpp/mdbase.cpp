#include "mdbase.h"

namespace tokza{
    MDBASE::MDBASE(CONFHANDLE& confhandle__):confhandle(confhandle__){
        this->flag = false;
        this->dec_conf = nullptr;
        return;
    }

    MDBASE::~MDBASE() {
        for(auto& obj :idx_key){
            delete obj.second;
        }
        idx_key.clear();
        hash_key.clear();
        return;
    }

    bool MDBASE::init() {
        // ...
        this->dec_conf = confhandle.get_dec_conf();
        if(nullptr==this->dec_conf){
            LOGD("MDBASE::init(),fail.\n");
            return false;
        }

        vector<u32> vec;
        bool ret = confhandle.get_type_vec(CONF_TYPE::TYPE_LIB_NAME,vec);
        if(!ret){
            LOGD("MDBASE::init(),fail.\n");
            return false;
        }
        for(auto& idx:vec){
            MD_INFO *stc = sub_init(idx);
            if (nullptr == stc) {
                LOGD("MDBASE::init(),fail.\n");
                return false;
            } else {
                this->hash_key.INSERT(stc->hash, stc);
                this->idx_key.INSERT(stc->index, stc);
            }
        }//for
        return true;
    }

    MD_INFO* MDBASE::sub_init(u32 idx) {
        MD_INFO* stc = new MD_INFO;
        stc->index = idx;
        stc->hash = str_utils.get_confelfhash_by_idx(this->dec_conf,idx);
        stc->md_base = utils.find_mdbase_by_maps(
                str_utils.get_encconf_by_idx(this->dec_conf,idx),
                str_utils.get_encconf_by_idx(this->dec_conf,this->dec_conf->idx_procpidmaps)
        );
        if(0==stc->md_base){
            return nullptr;
        }else{
            return stc;
        }//if
    }

    u32 MDBASE::getbyhash(u32 hash) {
        // init
        if(!this->flag){
            if(!this->init())
                return 0;
            this->flag = true;
        }

        // find
        auto it = hash_key.find(hash);
        if(it==hash_key.end()){
            return 0;
        }else{
            return it->second->md_base;
        }
    }

    u32 MDBASE::getbyidx(u32 idx) {
        // init
        if(!this->flag){
            if(!this->init())
                return 0;
            this->flag = true;
        }

        // find
        auto it = idx_key.find(idx);
        if(it==idx_key.end()){
            return 0;
        }else{
            return it->second->md_base;
        }
    }

    u32 MDBASE::get_libc() {
        // init
        if(!this->flag){
            if(!this->init())
                return 0;
            this->flag = true;
        }
        return this->getbyidx(this->dec_conf->idx_libname_libcso);
    }

    u32 MDBASE::get_self() {
        // init
        if(!this->flag){
            if(!this->init())
                return 0;
            this->flag = true;
        }
        return this->getbyidx(this->dec_conf->idx_libname_self);
    }
}

#include "func.h"

namespace tokza{
    FUNC_ELE::FUNC_ELE() {
        this->idx_libname = 0;
        this->head = 0;
        this->end = 0;
        this->filehash = 0;
        this->md_base = 0;
        this->addr = 0;
        return;
    }

    FUNC_ELE::~FUNC_ELE() {
        this->idx_libname = 0;
        this->head = 0;
        this->end = 0;
        this->filehash = 0;
        this->md_base = 0;
        this->addr = 0;
        return;
    }

    FUNC::FUNC(CONFHANDLE& confhandle__,MDBASE& mdbase__) :confhandle(confhandle__),mdbase(mdbase__){
        flag = false;
        dec_conf = confhandle.get_dec_conf();
        if(nullptr==dec_conf){
            LOGD("FUNC::FUNC(),fail.\n");
            FAIL_EXIT;
        }
        return;
    }

    FUNC::~FUNC() {
        flag = false;
        for(auto& t : m){
            delete t.second;
        }
        m.clear();
    }

    bool FUNC::initmap() {
        vector<u32> vec;
        bool ret = confhandle.get_type_vec(CONF_TYPE::TYPE_FUNC_ELE,vec);
        if(!ret){
            LOGD("FUNC::initmap(),fail.\n");
            return false;
        }
        for(auto& idx:vec){
            FUNC_ELE* t = this->getele(idx);
            if (nullptr == t) {
                LOGD("FUNC::initmap(),fail.\n");
                return false;
            }
            this->m.INSERT(t->addr,t);
        }//for
        return true;
    }

    FUNC_ELE* FUNC::getele(u32 idx) {
        // @@idx_libname##@@head##@@end##@@hash##
        STR_UTILS su;
        char* dec = su.get_decconf_by_idx(this->dec_conf,idx);
        char* p1 = su.getpart(dec,1);
        char* p2 = su.getpart(dec,2);
        char* p3 = su.getpart(dec,3);
        char* p4 = su.getpart(dec,4);
        if(NULL==p1||NULL==p2||NULL==p3||NULL==p4){
            LOGD("FUNC::getele(),fail.\n");
            return nullptr;
        }

        // ...
        FUNC_ELE* t = new FUNC_ELE;
        t->idx_libname = su.str2num(p1);
        t->head = su.str2num(p2);
        t->end = su.str2num(p3);
        t->filehash = su.str2num(p4);
        t->md_base = this->mdbase.getbyidx(t->idx_libname);
        t->addr = t->md_base + t->head;
        if(0==t->md_base){
            LOGD("FUNC::getele(),fail.\n");
            return nullptr;
        }

        // ...
        return t;
    }

    bool FUNC::check(u32* arr_func_addr, u32 count) {
        // 1 初始化
        if(!this->flag){
            if(!this->initmap()){
                LOGD("FUNC::getele(),fail.\n");
                FAIL_EXIT;
            }
            this->flag = true;
        }//if

        // 2 遍历函数地址数组
        for(u32 k=0; k < count; k++){
            u32 func_addr = arr_func_addr[k];
            // 调用单个函数检查逻辑
            if(this->check_single(func_addr)) {
                // 判定为HOOK
                return true;
            }
        }//for
        return false;
    }

    bool FUNC::check_single(u32 func_addr) {
        if( 0 != func_addr%2 ){
            func_addr -= 1;
        }
        auto it = this->m.find(func_addr);
        if(m.end()==it){
            // 没有找到该函数,检测失败,当成没有检测到HOOK.
            return false;
        }else{
            FUNC_ELE& obj = *(it->second);
            u32 v = str_utils.membkdrhash_half(obj.md_base,obj.head,obj.end);
            if(obj.filehash == v){
                return false;
            }else{
                LOGD("FUNC::check_single(),find func hook.\n");
                return true;
            }
        }//ifelse
    }

}
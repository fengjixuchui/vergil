#include "got.h"

namespace tokza {
    GOT_ELE::GOT_ELE() {
        this->idx_gotitem = 0;
        this->idx_libname= 0;
        this->elfhash_symname= 0;
        this->gotitem= 0;
        this->sym_addr= 0;
        return;
    }

    GOT_ELE::~GOT_ELE() {
        this->idx_gotitem = 0;
        this->idx_libname= 0;
        this->elfhash_symname= 0;
        this->gotitem= 0;
        this->sym_addr= 0;
        return;
    }

    GOT::GOT(CONFHANDLE& confhandle__, MDBASE& mdbase__) : confhandle(confhandle__), mdbase(mdbase__) {
        flag = false;
        is_hook = 0;
        head = 0;
        end = 0;
        hash = 0;
        dec_conf = confhandle.get_dec_conf();
        if(nullptr==dec_conf){
            LOGD("GOT::GOT(),fail.\n");
            FAIL_EXIT;
        }
        return;
    }

    GOT::~GOT() {
        for(auto& t:m){
            delete t.second;
        }
        flag = false;
        is_hook = 0;
        head = 0;
        end = 0;
        hash = 0;
        dec_conf = nullptr;
        m.clear();
    }

    bool GOT::initsec() {
        STR_UTILS su;
        if(nullptr==this->dec_conf){
            LOGD("GOT::initsec(),fail.\n");
            return false;
        }

        auto& mulmap = *confhandle.get_map();
        auto it = mulmap.find(CONF_TYPE::TYPE_GOT_SEC);
        if( 1!=mulmap.count(CONF_TYPE::TYPE_GOT_SEC) ){
            LOGD("GOT::initsec(),fail.\n");
            return false;
        }

        u32 idx = it->second;
        char* dec = su.get_decconf_by_idx(this->dec_conf, idx);
        char* p1 = su.getpart(dec, 1);
        char* p2 = su.getpart(dec, 2);
        if (NULL == p1 || NULL == p2) {
            LOGD("GOT::initsec(),fail.\n");
            return false;
        } else {
            // !
            this->head = su.str2num(p1);
            this->end = su.str2num(p2);
            return true;
        }
    }

    bool GOT::initmap() {
        vector<u32> vec;
        bool ret = confhandle.get_type_vec(CONF_TYPE::TYPE_GOT_ELE,vec);
        if(!ret){
            LOGD("GOT::initmap(),fail.\n");
            return false;
        }
        // !
        for(auto& idx:vec){
            GOT_ELE* t = this->getele(idx);
            if (nullptr == t) {
                LOGD("GOT::initmap(),fail.\n");
                return false;
            }
            this->m.INSERT(t->elfhash_symname, t);
        }//for
        return true;
    }

    GOT_ELE* GOT::getele(u32 idx) {
        // @@idx_gotitem##@@idx_libname##@@elfhash_symname##@@NULL##
        STR_UTILS su;
        char* dec = su.get_decconf_by_idx(this->dec_conf,idx);
        char* p1 = su.getpart(dec,1);
        char* p2 = su.getpart(dec,2);
        char* p3 = su.getpart(dec,3);
        if(NULL==p1||NULL==p2||NULL==p3){
            LOGD("GOT::getele(),fail.\n");
            return nullptr;
        }

        // ...
        GOT_ELE* t = new GOT_ELE;
        t->idx_gotitem = su.str2num(p1);
        t->idx_libname = su.str2num(p2);
        t->elfhash_symname = su.str2num(p3);
        t->gotitem = getgotitem(t);
        t->sym_addr = getsymaddr(t);
        if(0==t->sym_addr || 0==t->gotitem){
            LOGD("GOT::getele(),fail.\n");
            return nullptr;
        }

        // 检测HOOK
        if(t->gotitem != t->sym_addr){
            this->is_hook += IS_HOOK;
            LOGD("GOT::getele(),find gottab hook.\n");
        }

        // 返回新建元素
        return t;
    }

    u32 GOT::getgotitem(GOT_ELE* p) {
        u32 self_mdbase = mdbase.get_self();
        if(0==self_mdbase){
            LOGD("GOT::getgotitem(),fail.\n");
            return 0;
        }

        // 计算GOT项地址
        u32* got_tab_head_addr = (u32*)(self_mdbase + this->head);
        u32* got_item_addr = got_tab_head_addr + p->idx_gotitem;

        // 读取内容返回
        return *got_item_addr;
    }

    u32 GOT::getsymaddr(GOT_ELE* p) {
        // 查找基址
        u32 base = this->mdbase.getbyidx(p->idx_libname);
        if(0==base){
            LOGD("GOT::getsymaddr(),fail.\n");
            return 0;
        }

        // 查找符号地址
        u32 addr = 0;
        u32 size = 0;
        UTILS utils;
        bool ret = utils.my_dlsym(base,p->elfhash_symname,&addr,&size);
        if(!ret){
            LOGD("GOT::getsymaddr(),fail.\n");
            return 0;
        }else{
            return addr;
        }//if
    }

    bool GOT::gethash() {
        // 模块基址
        u32 self_mdbase = this->mdbase.get_self();
        if (0 == self_mdbase) {
            LOGD("GOT::gethash(),fail.\n");
            return false;
        }//if

        // 计算hash
        STR_UTILS su;
        this->hash = su.membkdrhash_half(self_mdbase,this->head,this->end);

        // ...
        if( 0==this->dec_conf->gottab_hash ){
            // 首次调用
            this->dec_conf->gottab_hash = this->hash;
            return true;
        }else{
            // 二次调用,进行检测HOOK
            if(this->dec_conf->gottab_hash != this->hash){
                this->is_hook += IS_HOOK;
                LOGD("GOT::gethash(),find gottab hook.\n");
            }
            return true;
        }//ifelse
    }

    bool GOT::check() {
        // (0)初始化时机：获取sec 获取map 获取hash
        // (1)RT时机，对象未释放：获取hash
        // (2)RT时机，对象被释放重新创建对象：获取sec、获取hash
        // (4)都不是

        // 0
        if(0 == this->dec_conf->gottab_hash && false==this->flag){
            this->is_hook = 0;
            if (!initsec() || !initmap() || !gethash()) {
                LOGD("GOT::check(),fail.\n");
                FAIL_EXIT;
            } else {
                this->flag = true;
                if (0 == this->is_hook)
                    return false;
                else
                    return true;
            }
        }

        // 1
        if(0 != this->dec_conf->gottab_hash && true==this->flag){
            this->is_hook = 0;
            if (!gethash()) {
                LOGD("GOT::check(),fail.\n");
                FAIL_EXIT;
            } else {
                if (0 == this->is_hook)
                    return false;
                else
                    return true;
            }
        }

        // 2
        if(0 != this->dec_conf->gottab_hash && false==this->flag){
            this->is_hook = 0;
            if (!initsec()  || !gethash()) {
                LOGD("GOT::check(),fail.\n");
                FAIL_EXIT;
            } else {
                this->flag = true;
                if (0 == this->is_hook)
                    return false;
                else
                    return true;
            }
        }

        // 4
        LOGD("GOT::check(),fail.\n");
        FAIL_EXIT;
    }

}
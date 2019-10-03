#include "sys.h"
#include "conf.h"

namespace tokza{
    SYS_ELE::SYS_ELE() {
        md_path = 0;
        md_name = 0;
        sym_name = 0;
        buf = 0;
        md_base = 0;
        fhead = 0;
        fend = 0;
        fhash = 0;
        mhead = 0;
        mend = 0;
        mhash = 0;
        return;
    }

    SYS_ELE::~SYS_ELE() {
        md_path = 0;
        md_name = 0;
        sym_name = 0;
        buf = 0;
        md_base = 0;
        fhead = 0;
        fend = 0;
        fhash = 0;
        mhead = 0;
        mend = 0;
        mhash = 0;
        return;
    }

    SYS::SYS(CONFHANDLE& confhandle__,MDBASE& mdbase__):confhandle(confhandle__),mdbase(mdbase__){
        this->flag = false;
        this->is_hook = 0;
        this->dec_conf = confhandle.get_dec_conf();
        if(nullptr==this->dec_conf){
            LOGD("SYS::SYS(),fail.\n");
            FAIL_EXIT;
        }
        return;
    }

    SYS::~SYS() {
        this->flag = false;
        this->is_hook = 0;
        for(auto& e:this->msysele){
            delete e.second;
        }//for
        this->mem.close();
    }

    bool SYS::init() {
        // 创建msyslib
        vector<u32> vec_syslib;
        bool ret = confhandle.get_type_vec(CONF_TYPE::TYPE_SYSLIB_PATH,vec_syslib);
        if(!ret){
            LOGD("SYS::init(),fail.\n");
            return false;
        }
        for(auto& idx:vec_syslib) {
            u8 *buf = sub_init_syslib(idx);
            if (nullptr == buf) {
                LOGD("SYS::init(),fail.\n");
                return false;
            }
            this->msyslib.INSERT(idx, buf);
        }//for

        // 创建SYS_ELE
        vector<u32> vec_sysele;
        ret = confhandle.get_type_vec(CONF_TYPE::TYPE_SYS_ELE,vec_sysele);
        if(!ret){
            LOGD("SYS::init(),fail.\n");
            return false;
        }
        for(auto& idx:vec_sysele) {
            SYS_ELE* ele = sub_init_sysele(idx);
            if (nullptr == ele) {
                LOGD("SYS::init(),fail.\n");
                return false;
            }
            this->msysele.INSERT(ele->sym_name, ele);
        }//for
        return true;
    }

    u8* SYS::sub_init_syslib(u32 idx) {
        STR_UTILS su;
        char* enc = su.get_encconf_by_idx(this->dec_conf,idx);
        u32 size = utils.get_filesz(enc);
        u8* buf = (u8*)mem.get(size);
        bool ret = utils.readfile_tomem(enc,buf,size);
        if(!ret){
            LOGD("SYS::sub_init_syslib(),fail.\n");
            return nullptr;
        }
        return buf;
    }

    SYS_ELE* SYS::sub_init_sysele(u32 idx) {
        // 举例 @@md_path##@@md_name##@@sym_name_hash##@@NULL##
        // ...
        STR_UTILS su;
        char* dec = su.get_decconf_by_idx(this->dec_conf,idx);
        char* p1 = su.getpart(dec,1);
        char* p2 = su.getpart(dec,2);
        char* p3 = su.getpart(dec,3);
        char* p4 = su.getpart(dec,4);
        if (NULL == p1 || NULL == p2 || NULL == p3) {
            LOGD("SYS::sub_init_sysele(),fail.\n");
            return nullptr;
        }

        // ...
        auto t = new SYS_ELE;
        t->md_path = (u32)(su.str2num(p1));
        t->md_name = (u32)(su.str2num(p2));
        t->sym_name = (u32)(su.str2num(p3));

        // buf
        auto it = this->msyslib.find(t->md_path);
        if(this->msyslib.end()==it){
            LOGD("SYS::sub_init_sysele(),fail.\n");
            return nullptr;
        }
        t->buf = it->second;

        // md_base
        t->md_base = this->mdbase.getbyidx(t->md_name);
        if(0==t->md_base){
            LOGD("SYS::sub_init_sysele(),fail.\n");
            return nullptr;
        }

        // fhead fend
        // bool file_dlsym(u32 buf_base, u32 elfhash_name,u32* output_addr,u32* output_sz);  // 失败时返回false、文件中符号查找
        u32 output_addr = 0;
        u32 output_sz = 0;
        bool ret = utils.file_dlsym((u32)(t->buf),t->sym_name,&output_addr,&output_sz);
        if(!ret){
            LOGD("SYS::sub_init_sysele(),fail.\n");
            return nullptr;
        }
        t->fhead = output_addr - (u32)(t->buf);
        t->fend = t->fhead + output_sz;
        t->fhash = 0;

        // mhead mend
        // bool my_dlsym(u32 mdbase, u32 elfhash_name,u32* output_addr,u32 *output_sz);
        output_addr = 0;
        output_sz = 0;
        ret = utils.my_dlsym(t->md_base,t->sym_name,&output_addr,&output_sz);
        if(!ret){
            LOGD("SYS::sub_init_sysele(),fail.\n");
            return nullptr;
        }
        t->mhead = output_addr - t->md_base;
        t->mend = t->mhead + output_sz;
        t->mhash = 0;

        // ...
        return t;
    }

    void SYS::get_hash() {
        STR_UTILS su;
        for(auto& e:this->msysele){
            u32 md_base = e.second->md_base;
            u32 buf = (u32)(e.second->buf);
            u32& fhead = e.second->fhead;
            u32& fend = e.second->fend;
            u32& fhash = e.second->fhash;
            u32& mhead = e.second->mhead;
            u32& mend = e.second->mend;
            u32& mhash = e.second->mhash;
            fhash = su.membkdrhash_half(buf,fhead,fend);
            mhash = su.membkdrhash_half(md_base, mhead,mend);
            if(fhash != mhash){
                this->is_hook = IS_HOOK;
                LOGD("SYS::get_hash(),fail.\n");
            }
        }//for
    }

    bool SYS::check() {
        // ...
        if(!this->flag){
            if(!init()){
                LOGD("SYS::check(),fail.\n");
                FAIL_EXIT;
            }
            this->flag = true;
        }

        // ...
        get_hash();
        if(0 != this->is_hook){
            return true;
        }else{
            return false;
        }
    }

}
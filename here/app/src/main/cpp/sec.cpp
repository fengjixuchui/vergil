#include "sec.h"

namespace tokza{
    SEC_ELE::SEC_ELE() {
        this->head = 0;
        this->end = 0;
        this->file_hash = 0;
        this->mem_hash = 0;
        return;
    }

    SEC_ELE::~SEC_ELE() {
        this->head = 0;
        this->end = 0;
        this->file_hash = 0;
        this->mem_hash = 0;
        return;
    }

    SEC::SEC(CONFHANDLE& confhandle__, MDBASE& mdbase__):confhandle(confhandle__),mdbase(mdbase__) {
        this->flag = false;
        this->is_hook = 0;

        this->dec_conf = confhandle.get_dec_conf();
        if(nullptr==dec_conf){
            LOGD("FUNC::FUNC(),fail.\n");
            FAIL_EXIT;
        }
        return;
    }

    SEC::~SEC() {
        flag = false;
        is_hook = 0;
        dec_conf = nullptr;
        return;
    }

    bool SEC::init() {
        vector<u32> vec;
        bool ret = this->confhandle.get_type_vec(CONF_TYPE::TYPE_SEC_ELE,vec);
        if(!ret){
            LOGD("SEC::init(),fail.\n");
            return false;
        }

        // 举例 @@type##@@head##@@end##@@filehash##(段信息)
        STR_UTILS su;
        for(auto& idx:vec){
            char* dec = su.get_decconf_by_idx(this->dec_conf,idx);
            char* p1 = su.getpart(dec,1);
            char* p2 = su.getpart(dec,2);
            char* p3 = su.getpart(dec,3);
            char* p4 = su.getpart(dec,4);
            if (NULL == p1 || NULL == p2 || NULL == p3 || NULL == p4) {
                LOGD("SEC::init(),fail.\n");
                return false;
            }

            SEC_TYPE sec_type = (SEC_TYPE)(su.str2num(p1));
            u32 head = (u32)(su.str2num(p2));
            u32 end = (u32)(su.str2num(p3));
            u32 filehash = (u32)(su.str2num(p4));
            if(SEC_TYPE::TYPE_DYNSYM ==sec_type){
                sub_init(this->LOAD1.dynsym,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_DYNSTR ==sec_type){
                sub_init(this->LOAD1.dynstr,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_HASH ==sec_type){
                sub_init(this->LOAD1.hash,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_RELDYN ==sec_type){
                sub_init(this->LOAD1.reldyn,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_RELPLT ==sec_type){
                sub_init(this->LOAD1.relplt,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_PLT ==sec_type){
                sub_init(this->LOAD1.plt,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_ARMEXTAB ==sec_type){
                sub_init(this->LOAD1.arm_extab,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_ARMEXIDX ==sec_type){
                sub_init(this->LOAD1.arm_exidx,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_RODATA ==sec_type){
                sub_init(this->LOAD1.rodata,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_FINIARRAY ==sec_type){
                sub_init(this->LOAD2.fini_array,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_INITARRAY ==sec_type){
                sub_init(this->LOAD2.init_array,head,end,filehash);
            }
            else if(SEC_TYPE::TYPE_DYNAMIC ==sec_type){
                sub_init(this->LOAD2.dynamic,head,end,filehash);
            }else{
                LOGD("SEC::init(),fail.\n");
                return false;
            }//ifelse
        }//for
        return true;
    }

    void SEC::sub_init(SEC_ELE& ele, u32 head, u32 end, u32 file_hash) {
        ele.head = head;
        ele.end = end;
        ele.file_hash =file_hash;
        return;
    }

    void SEC::get_memhash() {
        u32 base = this->mdbase.get_self();
        sub_getmemhash(this->LOAD1.dynsym,base);
        sub_getmemhash(this->LOAD1.dynstr,base);
        sub_getmemhash(this->LOAD1.hash,base);
        sub_getmemhash(this->LOAD1.reldyn,base);
        sub_getmemhash(this->LOAD1.relplt,base);
        sub_getmemhash(this->LOAD1.plt,base);
        sub_getmemhash(this->LOAD1.arm_extab,base);
        sub_getmemhash(this->LOAD1.arm_exidx,base);
        sub_getmemhash(this->LOAD1.rodata,base);
        sub_getmemhashload2(this->LOAD2.fini_array,base);
        sub_getmemhashload2(this->LOAD2.init_array,base);
        sub_getmemhash(this->LOAD2.dynamic,base);
        return;
    }

    void SEC::sub_getmemhash(SEC_ELE& ele,u32 base) {
        ele.mem_hash = str_utils.membkdrhash_half(base,ele.head,ele.end);
        if(ele.mem_hash != ele.file_hash){
            this->is_hook += IS_HOOK;
            LOGD("SEC::sub_getmemhash(),find sec hook.\n");
        }
        return;
    }

    void SEC::sub_getmemhashload2(SEC_ELE& ele, u32 base) {
        if(ele.end <= ele.head){
            ele.mem_hash = 0;
            return;
        }
        MEM mem;
        u8* addr = (u8*)(ele.head + base);
        u32 size = (ele.end - ele.head);
        u32* buf = (u32*)(mem.get(size));
        u32 count = size / 4;
        memcpy(buf, addr, size);
        for (u32 k = 0; k < count; k++) {
            if (0 == buf[k])
                continue;
            else
                buf[k] = buf[k] - base;
        }//for
        ele.mem_hash  = str_utils.membkdrhash_half( 0, (u32)buf,(u32)buf + size );
        if(ele.mem_hash != ele.file_hash){
            this->is_hook += IS_HOOK;
            LOGD("SEC::sub_getmemhashload2(),find sec hook.\n");
        }
        return;
    }

    bool SEC::check() {
        // 初始化
        if(!this->flag){
            if(!init()){
                FAIL_EXIT;
            }
            this->flag = true;
        }

        // 实时计算内存hash，与预设对比后返回结果
        this->is_hook = 0;
        get_memhash();
        if( 0!=this->is_hook ){
            return true;
        }else{
            return false;
        }
    }

}
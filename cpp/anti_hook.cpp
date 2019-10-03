#include "anti_hook.h"
#include "mdbase.h"
#include "got.h"
#include "func.h"
#include "sec.h"
#include "sys.h"
using namespace std;
using namespace tokza;

STRUCT AHSTC{
    AHSTC();
    ~AHSTC();
    CONFHANDLE* confhandle;
    MDBASE* mdbase;
    GOT* got;
    FUNC* func;
    SEC* sec;
    SYS* sys;
}AHSTC;

AHSTC::AHSTC() {
    confhandle = nullptr;
    mdbase = nullptr;
    got = nullptr;
    func = nullptr;
    sec = nullptr;
    sys = nullptr;
    return;
}

AHSTC::~AHSTC() {
    if(nullptr!=sys){
        delete sys;
        sys = nullptr;
    }

    if(nullptr!=sec){
        delete sec;
        sec = nullptr;
    }

    if(nullptr!=func){
        delete func;
        func = nullptr;
    }

    if(nullptr!=got){
        delete got;
        got = nullptr;
    }

    if(nullptr!=mdbase){
        delete mdbase;
        mdbase = nullptr;
    }

    if(nullptr!=confhandle){
        delete confhandle;
        confhandle = nullptr;
    }
    return;
}

void close_obj(bool is_close,AHSTC& ahstc){
    if(is_close){
        ahstc.confhandle->get_dec_conf()->obj = 0;
        ahstc.confhandle->save();
        delete &ahstc;
    }else{
        ahstc.confhandle->get_dec_conf()->obj = (u32)&(ahstc);
        ahstc.confhandle->save();
    }
    return;
}

bool check_obj(bool is_close,AHSTC& ahstc,uint32_t* arr_func, uint32_t count){
    if( ahstc.got->check() ||
        ahstc.func->check(arr_func,count)||
        ahstc.sec->check() ||
        ahstc.sys->check()
            ){
        close_obj(is_close,ahstc);
        return true;
    }else{
        close_obj(is_close,ahstc);
        return false;
    }
}

bool anti_hook(ANTI_HOOK* global, bool is_close, uint32_t* arr_func, uint32_t count){
    // 读取CONF
    CONF& conf = *(CONF*)global;
    CONFHANDLE& confhandle = *(new CONFHANDLE(&conf));
    CONF* dec_conf = confhandle.get_dec_conf();
    if(nullptr==dec_conf){
        delete &confhandle;
        return true;
    }

    // 检查存在未释放对象
    if(0==dec_conf->obj){
        // (1) 不存在
        AHSTC& ahstc = *(new AHSTC);
        ahstc.confhandle = &confhandle;
        ahstc.mdbase = new MDBASE(*ahstc.confhandle);
        ahstc.got = new GOT(*ahstc.confhandle,*ahstc.mdbase);
        ahstc.func = new FUNC(*ahstc.confhandle,*ahstc.mdbase);
        ahstc.sec = new SEC(*ahstc.confhandle,*ahstc.mdbase);
        ahstc.sys = new SYS(*ahstc.confhandle,*ahstc.mdbase);

        // check
        return check_obj(is_close,ahstc,arr_func,count);
    }else{
        // (2) 存在
        AHSTC& ahstc = *(AHSTC*)(dec_conf->obj);
        delete &confhandle;

        // check
        return check_obj(is_close,ahstc,arr_func,count);
    }
}
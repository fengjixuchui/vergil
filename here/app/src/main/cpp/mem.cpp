#include "mem.h"
namespace tokza{
    MEM::MEM() {
        sum_sz = 0;
    }

    MEM::~MEM() {
        close();
    }

    void* MEM::get(u32 size) {
        u8* p =new u8[size];
        memset(p,0,size);
        info.INSERT(p,size);
        sum_sz += size;
        return (void*)p;
    }

    void MEM::del(u8* p) {
        auto it = info.find(p);
        if(info.end()!=it) {
            sum_sz -= it->second;
            memset(it->first,0,it->second);
            delete (it->first);
            info.erase(it->first);
            return;
        }
    }

    void MEM::close() {
        for(auto& obj:info){
            memset(obj.first,0,obj.second);
            delete obj.first;
        }
        info.clear();
        sum_sz = 0;
        return;
    }

}
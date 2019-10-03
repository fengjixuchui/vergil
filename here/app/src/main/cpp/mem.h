#pragma once
#include "base.h"
namespace tokza{
    class MEM{
    public:
        MEM();
        ~MEM();
        void* get(u32 size);
        void del(u8* p);
        void close();
    private:
        u32 sum_sz;
        map<u8*,u32> info;
    };
}

/*
 * OK!
    MEM& mem = *(new tokz::MEM);
    u8* p1 = (u8*)mem.get(11);
    u8* p2 = (u8*)mem.get(12);
    u8* p3 = (u8*)mem.get(13);
    u8* p4 = (u8*)mem.get(14);
    mem.del(p2);
    mem.del(p3);
    mem.del(p3);
    mem.close();
    delete(&mem);
*/
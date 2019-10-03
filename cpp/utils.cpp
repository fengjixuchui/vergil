#include "utils.h"

namespace tokza{

    UTILS::UTILS() {
    }

    UTILS::~UTILS() {
    }

    u32 UTILS::find_mdbase_by_maps(char* enc_mdname, char* enc_procpidmaps) {
        MEM mem;
        STR_UTILS su;

        // 申请内存空间
        char* path = (char*)mem.get(255);
        char* line = (char*)mem.get(1024);

        // 解密字符串
        char* dec_mdname = su.decstr(enc_mdname,STR_UTILS_IS_DEBUG);
        char* dec_proc = su.decstr(enc_procpidmaps,STR_UTILS_IS_DEBUG);

        // 获取maps路径
        if( -1==snprintf(path, 254,(cchar*)dec_proc, getpid()) ){
            LOGD("UTILS::find_mdbase_by_maps(),fail.\n");
            return 0;
        }

        // 打开maps
        FILE* fp = fopen(path,"r");
        if( NULL==fp ){
            LOGD("UTILS::find_mdbase_by_maps(),fail.\n");
            return 0;
        }

        // 查找模块基址
        char* p =NULL;
        u32 addr = 0;
        while (fgets(line, 1023, fp)) {
            if (strstr(line, dec_mdname)) {
                p = strtok(line, "-");
                addr = strtoul((const char*)p, NULL, 16);
                if (addr == 0x8000)
                    addr = 0;
                break;
            }//if
        }//while

        // 返回
        if( 0==addr ){
            LOGD("UTILS::find_mdbase_by_maps(),fail.\n");
        }
        fclose(fp);
        return addr;
    }

    bool UTILS::my_dlsym(u32 mdbase, u32 elfhash_name, u32* output_addr, u32* output_sz) {
        u32 k = 0;
        u32 i = 0;
        Elf32_Ehdr *ehdr = NULL;
        Elf32_Phdr *phdr = NULL;
        Elf32_Dyn* p_dynamic = NULL;
        Elf32_Dyn* d = NULL;
        Elf32_Sym* p_symtab = NULL;
        Elf32_Sym* t = NULL;
        u32 hash = 0;
        u32* p_bucket = NULL;
        u32* p_chain = NULL;
        u32 nbucket = 0;
        char* strtab = NULL;
        u32 strz = 0;
        bool flag = false;
        u32 mod = 0;

        // check
        if( 0==mdbase || 0==elfhash_name || NULL==output_addr || NULL==output_sz ){
            LOGD("UTILS::my_dlsym(),fail.\n");
            return false;
        }

        // ELF头、段表
        ehdr = (Elf32_Ehdr*)mdbase;
        phdr = (Elf32_Phdr*)(mdbase + (u32)ehdr->e_phoff);

        // 查找PT_DYNAMIC
        for (k = 0; k < ehdr->e_phnum; ++k) {
            if(PT_DYNAMIC==phdr->p_type) {
                p_dynamic = (Elf32_Dyn*)((u32)phdr->p_vaddr + mdbase);
                break;
            }
            ++phdr;
        }//for
        if( NULL==p_dynamic ){
            LOGD("UTILS::my_dlsym(),fail.\n");
            return false;
        }

        // 查找四个子对象
        for(d = p_dynamic; DT_NULL != d->d_tag; ++d) {
            if(d->d_tag == DT_SYMTAB) {
                p_symtab = (Elf32_Sym*)(d->d_un.d_ptr + mdbase);
                t = p_symtab;
            }
            if(d->d_tag == DT_HASH) {
                hash = (u32)(d->d_un.d_ptr + mdbase);
                nbucket = *((u32*)hash);
                p_bucket = (u32*)(hash+8);
                p_chain = (u32*)(hash + 4 * (2 + nbucket));
            }
            if(d->d_tag == DT_STRTAB) {
                strtab = (char*)(d->d_un.d_ptr + mdbase);
            }
            if(d->d_tag == DT_STRSZ) {
                strz = (u32)(d->d_un.d_val);
            }
        }//for
        if( NULL==p_symtab || 0==hash || NULL==strtab || 0==strz ){
            LOGD("UTILS::my_dlsym(),fail.\n");
            return false;
        }

        // 查找符号
        STR_UTILS su;
        flag = false;
        mod = (elfhash_name % nbucket);
        i = 0;
        for(i = p_bucket[mod]; i != 0; i = p_chain[i]) {
            if(su.elfhash(strtab + (p_symtab + i)->st_name) == elfhash_name) {
                flag = true;
                *output_addr = mdbase + (p_symtab + i)->st_value;
                *output_sz = (p_symtab + i)->st_size;
                break;
            }
        }//for

        // 清理内存
        k = 0;
        i = 0;
        ehdr = NULL;
        phdr = NULL;
        p_dynamic = NULL;
        d = NULL;
        p_symtab = NULL;
        t = NULL;
        hash = 0;
        p_bucket = NULL;
        p_chain = NULL;
        nbucket = 0;
        strtab = NULL;
        strz = 0;
        mod = 0;
        mdbase = 0;
        elfhash_name = 0;
        output_addr = NULL;
        output_sz= NULL;

        // ...
        return flag;
    }

    u32 UTILS::get_filesz(char* enc_path) {
        s32 fd = 0;
        s32 size = 0;

        // dec
        STR_UTILS su;
        char* dec_path = su.decstr(enc_path,STR_UTILS_IS_DEBUG);

        // ...
        fd = open(dec_path,O_RDONLY);
        if(-1==fd) {
            LOGD("UTILS::get_filesz(),open(),fail.\n");
            LOGD("errno=%d\n",errno);
            return 0;
        }

        size = lseek(fd,0,SEEK_END);
        if(-1==size){
            close(fd);
            LOGD("UTILS::get_filesz(),lseek(),fail.\n");
            LOGD("errno=%d\n",errno);
            return 0;
        }

        if(-1==close(fd)) {
            LOGD("UTILS::get_filesz(),close(),fail.\n");
            LOGD("errno=%d\n",errno);
            return 0;
        }

        if(0x7FFFFFFF<=size){
            LOGD("UTILS::get_filesz(),0x7FFFFFFF<=size,fail.\n");
            return 0;
        }

        // ...
        enc_path = NULL;
        dec_path = NULL;
        fd = 0;

        // ...
        return (u32)(size);
    }

    bool UTILS::readfile_tomem(char* enc_path, u8* buf, u32 size) {
        s32 fd = 0;
        s32 ret = 0;

        // check
        if( NULL==buf || 0==size ){
            LOGD("UTILS::readfile_tomem(),buf or size == NULL,fail.\n");
            return false;
        }

        // dec
        STR_UTILS su;
        char* dec_path = su.decstr(enc_path,STR_UTILS_IS_DEBUG);
        memset(buf,0,size);

        // ...
        fd = open(dec_path,O_RDONLY);
        if(-1==fd) {
            LOGD("UTILS::readfile_tomem(),open(),fail.\n");
            LOGD("errno=%d\n",errno);
            return false;
        }
        if(-1==lseek(fd, 0, SEEK_SET)){
            LOGD("UTILS::readfile_tomem(),lseek(),fail.\n");
            LOGD("errno=%d\n",errno);
            return false;
        }
        ret = (s32)read(fd,buf,size);
        if(-1==ret || size!=ret) {
            LOGD("UTILS::readfile_tomem(),read(),fail.\n");
            LOGD("errno=%d\n",errno);
            return false;
        }
        if(-1==close(fd)) {
            LOGD("UTILS::readfile_tomem(),close(),fail.\n");
            LOGD("errno=%d\n",errno);
            return false;
        }

        // ...
        enc_path = NULL;
        dec_path = NULL;
        buf = NULL;
        size = 0;
        fd = 0;
        ret = 0;

        // ...
        return true;
    }

    bool UTILS::file_dlsym(u32 buf_base, u32 elfhash_name, u32* output_addr, u32* output_sz) {
        u32 k = 0;
        u32 i = 0;
        Elf32_Ehdr *ehdr = NULL;
        Elf32_Phdr *phdr = NULL;
        Elf32_Dyn* p_dynamic = NULL;
        Elf32_Dyn* d = NULL;
        Elf32_Sym* p_symtab = NULL;
        Elf32_Sym* t = NULL;
        u32 hash = 0;
        u32* p_bucket = NULL;
        u32* p_chain = NULL;
        u32 nbucket = 0;
        char* strtab = NULL;
        u32 strz = 0;
        bool flag = false;
        u32 mod = 0;

        // check
        if( 0==buf_base || 0==elfhash_name || NULL==output_addr || NULL==output_sz){
            LOGD("UTILS::file_dlsym(),fail.\n");
            return false;
        }

        // ELF头、段表
        ehdr = (Elf32_Ehdr*)buf_base;
        phdr = (Elf32_Phdr*)(buf_base + (u32)ehdr->e_phoff);

        // 查找PT_DYNAMIC
        for (k = 0; k < ehdr->e_phnum; ++k) {
            if (PT_DYNAMIC == phdr->p_type) {
                p_dynamic = (Elf32_Dyn *) ((u32) phdr->p_offset + buf_base);
                break;
            }
            ++phdr;
        }//for
        if(NULL==p_dynamic){
            LOGD("UTILS::file_dlsym(),my_dlsym_fileoff(),fail.\n");
            return false;
        }

        // 查找四个子对象
        for(d = p_dynamic; DT_NULL != d->d_tag; ++d) {
            if(d->d_tag == DT_SYMTAB) {
                p_symtab = (Elf32_Sym*)(d->d_un.d_ptr + buf_base);
                t = p_symtab;
            }
            if(d->d_tag == DT_HASH) {
                hash = (u32)(d->d_un.d_ptr + buf_base);
                nbucket = *((u32*)hash);
                p_bucket = (u32*)(hash+8);
                p_chain = (u32*)(hash + 4 * (2 + nbucket));
            }
            if(d->d_tag == DT_STRTAB) {
                strtab = (char*)(d->d_un.d_ptr + buf_base);
            }
            if(d->d_tag == DT_STRSZ) {
                strz = (u32)(d->d_un.d_val);
            }
        }//for
        if(NULL==p_symtab || 0==hash || NULL==strtab || 0==strz){
            LOGD("UTILS::file_dlsym(),fail.\n");
            return false;
        }

        // 查找符号
        STR_UTILS su;
        flag = false;
        mod = (elfhash_name % nbucket);
        i = 0;
        for(i = p_bucket[mod]; i != 0; i = p_chain[i]) {
            if(su.elfhash(strtab + (p_symtab + i)->st_name) == elfhash_name) {
                flag = true;
                *output_addr = (u32)(buf_base + (u32)(p_symtab + i)->st_value);
                *output_sz = (u32)((p_symtab + i)->st_size);
                break;
            }//if
        }//for

        // 清理内存
        k = 0;
        i = 0;
        ehdr = NULL;
        phdr = NULL;
        p_dynamic = NULL;
        d = NULL;
        p_symtab = NULL;
        t = NULL;
        hash = 0;
        p_bucket = NULL;
        p_chain = NULL;
        nbucket = 0;
        strtab = NULL;
        strz = 0;
        mod = 0;
        buf_base = 0;
        elfhash_name = 0;
        output_addr = NULL;
        output_sz = NULL;
        // 返回
        return flag;
    }

}
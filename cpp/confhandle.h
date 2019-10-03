#pragma once
#include "base.h"
#include "conf.h"
#include "sm4.h"

namespace tokza{

    // 输入加密的CONF
    // 提供获取明文CONF的API
    // CONF中的CONF_ELE被建立为mulmap,提供访问某一类型CONF_ELE的API
    class CONFHANDLE{
    public:
        CONFHANDLE(CONF* g_conf__);
        ~CONFHANDLE();
    public:
        CONF* get_dec_conf();               // 失败时返回nullptr、返回解密的CONF
        multimap<CONF_TYPE,u32>* get_map(); // 失败时返回nullptr、返回mulmap
        void save();                        // 会改变构造函数输入g_conf__的值、将解密的CONF加密保存回全局变量
        bool get_type_vec(CONF_TYPE type,vector<u32>& vec);// 失败时返回false、获取某一个类型的下标集
    private:
        bool init_conf();                   // 初始化
        bool init_map();                    // 建立枚举类型map
    private:
        multimap<CONF_TYPE,u32> mulmap;     // map<type,idx>
        CONF* g_conf;                       // 原始的加密conf
        CONF* dec_conf;                     // 解密的conf
        SM4 sm4;                            // ...
        bool flag;                          // ...
    };
}
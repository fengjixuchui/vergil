#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <elf.h>
#include <android/log.h>
typedef uint8_t        u8;
typedef uint16_t       u16;
typedef uint32_t       u32;
typedef uint64_t       u64;
typedef int8_t         s8;
typedef int16_t        s16;
typedef int32_t        s32;
typedef int64_t        s64;
typedef const char     cchar;
typedef unsigned char  uchar;
typedef unsigned char  byte;
typedef unsigned long  ulong;
#define PAGE_START(x)  ((x) & PAGE_MASK)
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#define LOG_TAG        "C_TAG"
#define LOGD(...)      __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define STRUCT         typedef struct

#include <iostream>
#include <fstream>
#include <array>
#include <bitset>
#include <deque>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <stack>
#include <queue>
using namespace::std;
#define INSERT(a,b) insert(make_pair(a,b))
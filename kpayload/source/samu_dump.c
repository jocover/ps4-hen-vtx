#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "sections.h"
#include "sparse.h"
#include "offsets.h"
#include "freebsd_helper.h"
#include "ccp_helper.h"
#include "sbl_helper.h"
#include "amd_helper.h"

#define PAGE_SIZE 0x4000

#define ALIGN_SIZE(size, alignment) (((size) + ((alignment)-1)) & ~((alignment)-1))

#define ALIGN_PAGE(size) ALIGN_SIZE(size, PAGE_SIZE)

//#define ENABLE_DUMP_RAW_KEY
//#define ENABLE_DUMP_PORTABILITY_KEY
#define ENABLE_HOOK_PFS_KEY
//#define ENABLE_HOOK_PORTABILITY_KEY

extern void* (*malloc)(unsigned long size, void* type, int flags)PAYLOAD_BSS;
extern void (*free)(void* addr, void* type) PAYLOAD_BSS;
extern int (*sceSblKeymgrSetKey)(union sbl_key_desc* key, unsigned int* handle) PAYLOAD_BSS;
extern int (*sceSblKeymgrCleartKey)(uint32_t kh) PAYLOAD_BSS;
extern void* (*memcpy)(void* dst, const void* src, size_t len)PAYLOAD_BSS;
extern void* (*memset)(void* s, int c, size_t n)PAYLOAD_BSS;
extern int (*memcmp)(const void* ptr1, const void* ptr2, size_t num) PAYLOAD_BSS;
extern int (*sceSblServiceCrypt)(struct ccp_req* req) PAYLOAD_BSS;
extern int (*sceSblDriverUnmapPages)(struct sbl_map_list_entry*) PAYLOAD_BSS;
extern int (*sceSblDriverMapPages)(void** gpu_paddr, void* cpu_vaddr, uint32_t npages, uint64_t flags, void*,
                                   struct sbl_map_list_entry**) PAYLOAD_BSS;
extern int (*sceSblKeymgrSetKeyForPfs)(union sbl_key_desc* key, unsigned int* handle) PAYLOAD_BSS;
extern int (*printf)(const char* fmt, ...) PAYLOAD_BSS;
extern struct sbl_map_list_entry** SBL_DRIVER_MAPPED_PAGES PAYLOAD_BSS;
extern void* M_TEMP PAYLOAD_BSS;
extern void* PORTABILITY_KEY_DATA PAYLOAD_BSS;
PAYLOAD_CODE static inline void* alloc(uint32_t size) { return malloc(size, M_TEMP, 2); }

PAYLOAD_CODE static inline void dealloc(void* addr) { free(addr, M_TEMP); }

PAYLOAD_CODE static inline void hexdump(const void* data, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        printf("%02hhX%c", ((char*)data)[i], (i + 1) % 16 ? ' ' : '\n');
    }
    printf("\n");
}

#if defined(ENABLE_DUMP_RAW_KEY)
PAYLOAD_CODE int dump_raw_keys(unsigned int* key_ids, size_t key_count, unsigned int max_key_size, uint8_t** key_data,
                               size_t* key_data_size) {
    uint8_t* kd = NULL;
    size_t kds;
    void *buf = NULL, *m_buf = NULL;
    struct sbl_map_list_entry* d_buf = NULL;
    size_t buf_size = PAGE_SIZE;
    struct ccp_req req;
    struct ccp_msg msg;
    size_t data_size = 0x10;
    uint8_t current_key[0x40];
    uint8_t real_hash[0x20], our_hash[0x20];
    unsigned int key_index, key_size;
    uint8_t* ckd;
    unsigned int i, j;
    size_t c;
    int found;
    int ret;

    printf("Allocating memory for key data buffer...\n");
    kds = (max_key_size + sizeof(int)) * key_count;
    kd = (uint8_t*)alloc(kds);
    if (!kd) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    memset(kd, 0, kds);

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));

    TAILQ_INIT(&req.msgs);
    TAILQ_INSERT_TAIL(&req.msgs, &msg, next);

    printf("Allocating memory for data buffer...\n");
    buf = alloc(buf_size);
    if (!buf) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    printf("Data buffer CPU address: %p\n", buf);
    memset(buf, 0, buf_size);

    printf("Filling data buffer with random data...\n");
    for (i = 0; i < data_size; ++i) *((uint8_t*)buf + i) = (i + 1) & 0xFF;

    printf("Mapping data buffer to GPU...\n");
    size_t align_size = ALIGN_PAGE(buf_size);
    ret = sceSblDriverMapPages(&m_buf, buf, align_size, 0x61, NULL, &d_buf);
    if (ret != 0) {
        printf("Failed.\n");
        goto error;
    }
    printf("Data buffer GPU address: %p (d: %p)\n", m_buf, d_buf);

    for (c = 0; c < key_count; ++c) {
        key_index = key_ids[c];
        ckd = kd + (max_key_size + sizeof(int)) * c;

        printf("Bruteforcing key index: 0x%04X\n", key_index);

        memset(current_key, 0, sizeof(current_key));
        memset(real_hash, 0, sizeof(real_hash));
        memset(our_hash, 0, sizeof(our_hash));

        for (key_size = 0; key_size < max_key_size; ++key_size) {
            memset(&msg.op, 0, sizeof(msg.op));
            msg.op.hmac.cmd = 0x09034000 | CCP_USE_KEY_FROM_SLOT;
            msg.op.hmac.data_size = data_size;
            msg.op.hmac.data = buf;
            msg.op.hmac.data_size_bits = data_size * 8;
            msg.op.hmac.key_index = key_index;
            msg.op.hmac.key_size = key_size + 1;

            // printf("Preparing crypto request...\n");
            ret = sceSblServiceCrypt(&req);
            if (ret != 0) {
                *(int*)(ckd + max_key_size) = ret;
                printf("sceSblServiceCrypt(index) failed (code: 0x%" PRIX32 ").\n", ret);
                printf("\t0x%04X: N/A\n", key_index);
                break;
            }
            memcpy(real_hash, msg.op.hmac.hash, sizeof(real_hash));

            found = 0;
            for (i = 0; i < 256; ++i) {
                current_key[key_size] = (uint8_t)i;

                memset(&msg.op, 0, sizeof(msg.op));
                msg.op.hmac.cmd = 0x09034000;
                msg.op.hmac.data_size = data_size;
                msg.op.hmac.data = buf;
                msg.op.hmac.data_size_bits = data_size * 8;
                for (j = 0; j < (key_size + 1); ++j)
                    msg.op.hmac.key[(key_size + 1) - j - 1] = current_key[j]; /* reversed order */
                msg.op.hmac.key_size = key_size + 1;

                // printf("Preparing crypto request...\n");
                ret = sceSblServiceCrypt(&req);
                if (ret != 0) break;
                memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

                if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
                    current_key[key_size] = (uint8_t)i;
                    found = 1;
                    break;
                }
            }
            if (ret != 0) {
                *(int*)(ckd + max_key_size) = ret;
                printf("sceSblServiceCrypt(key) failed (code: 0x%" PRIX32 ").\n", ret);
                break;
            }
            if (found) {
                if (key_size == max_key_size - 1) {
                    *(int*)(ckd + max_key_size) = 0;
                    for (i = 0; i < max_key_size; ++i) ckd[i] = current_key[max_key_size - i - 1];
                    int is_empty = 1;
                    for (i = 0; i < max_key_size; ++i) {
                        if (ckd[i] != 0) {
                            is_empty = 0;
                        }
                    }

                    if (!is_empty) {
                        printf("\tFOUND\n");  // xts data and tweak keys or sig hmac key
                        hexdump(ckd, max_key_size);
                    }
                }
            } else {
                *(int*)(ckd + max_key_size) = ESRCH;
                // printf("\tNOT FOUND\n");
            }
        }
    }

    ret = 0;

    if (key_data) {
        *key_data = kd;
        kd = NULL;
    }
    if (key_data_size) *key_data_size = kds;

error:
    if (d_buf) {
        printf("Unmapping data buffer from GPU...\n");
        sceSblDriverUnmapPages(d_buf);
    }

    if (buf) {
        printf("Freeing memory of data buffer...\n");
        dealloc(buf);
    }

    if (kd) {
        printf("Freeing memory of key data buffer...\n");
        dealloc(kd);
    }

    return ret;
}
#endif

#if defined(ENABLE_DUMP_PORTABILITY_KEY)

PAYLOAD_CODE int get_keyid_offset(unsigned int keyid) {
    int offset = 0LL;
    switch (keyid) {
        case 0:
            break;
        case 4:
            offset = 0xC0LL;
            break;
        case 5:
            offset = 0x180LL;
            break;
        case 6:
            offset = 0x240LL;
            break;
        case 7:
            offset = 0x300LL;
            break;
        case 8:
            offset = 0x3C0LL;
            break;
        case 0xC:
            offset = 0x480LL;
            break;
        case 0xD:
            offset = 0x540LL;
            break;
        case 0x10:
            offset = 0x600LL;
            break;
        case 0x14:
            offset = 0x6C0LL;
            break;
        case 0x18:
            offset = 0x780LL;
            break;
        case 0x1C:
            offset = 0x840LL;
            break;
        case 0x20:
            offset = 0x900LL;
            break;
        case 0x24:
            offset = 0x9C0LL;
            break;
        case 0x28:
            offset = 0xA80LL;
            break;
        case 0x3C:
            offset = 0xB40LL;
            break;
        case 0x40:
            offset = 0xC00LL;
            break;
        case 0x44:
            offset = 0xCC0LL;
            break;
        case 0x48:
            offset = 0xD80LL;
            break;
        case 0x4C:
            offset = 0xE40LL;
            break;
        case 0x50:
            offset = 0xF00LL;
            break;
        case 0x54:
            offset = 0xFC0LL;
            break;
        case 0x58:
            offset = 0x1080LL;
            break;
    }
    return offset;
}

PAYLOAD_CODE int dump_gen_portability_keys(unsigned int cmd, int use_hmac, unsigned int max_key_size,
                                           unsigned int* key_ids, size_t key_count, uint8_t** key_data,
                                           size_t* key_data_size) {
    uint8_t* kd = NULL;
    size_t kds;
    void *buf = NULL, *m_buf = NULL;
    struct sbl_map_list_entry* d_buf = NULL;
    size_t buf_size = PAGE_SIZE;
    struct ccp_req req;
    struct ccp_msg msg;
    size_t data_size = 0x80;
    uint8_t current_key[0x40];
    uint8_t real_hash[0x20], our_hash[0x20];
    unsigned int key_index, key_size, key_index_mod;
    unsigned int key_handle = 0;
    union sbl_key_desc key_desc;
    uint8_t* ckd;
    unsigned int i, j;
    size_t c;
    int found;
    int ret;

    // printf("Allocating memory for key data buffer...\n");
    kds = (max_key_size + sizeof(int)) * key_count;
    kd = (uint8_t*)alloc(kds);
    if (!kd) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    memset(kd, 0, kds);

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));

    TAILQ_INIT(&req.msgs);
    TAILQ_INSERT_TAIL(&req.msgs, &msg, next);

    // printf("Allocating memory for data buffer...\n");
    buf = alloc(buf_size);
    if (!buf) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    // printf("Data buffer CPU address: %p\n", buf);
    memset(buf, 0, buf_size);

    // printf("Filling data buffer with random data...\n");
    for (i = 0; i < data_size; ++i) *((uint8_t*)buf + i) = (i + 1) & 0xFF;

    // printf("Mapping data buffer to GPU...\n");
    size_t align_size = ALIGN_PAGE(buf_size);
    ret = sceSblDriverMapPages(&m_buf, buf, align_size, 0x61, NULL, &d_buf);
    if (ret != 0) {
        printf("Failed.\n");
        goto error;
    }
    // printf("Data buffer GPU address: %p (d: %p)\n", m_buf, d_buf);

    key_index_mod = use_hmac ? 0x8000 : 0;

    for (c = 0; c < key_count; ++c) {
        key_index = key_ids[c];
        ckd = kd + (max_key_size + sizeof(int)) * c;

        printf("Bruteforcing key index: 0x%04X\n", key_index | key_index_mod);

        memset(&key_desc, 0, sizeof(key_desc));
        key_desc.portability.cmd = cmd;
        key_desc.portability.key_id = key_index | key_index_mod;

        int offset = get_keyid_offset(key_index);

        // TODO need gpu base address replace 0x19348000 this address
        // I use ENABLE_HOOK_PORTABILITY_KEY to get the key_desc dump and calculate the offset to get address
        uint64_t* key1 = (uint64_t*)&key_desc.portability.key1;
        *key1 = 0x19348000 + offset;

        uint64_t* key2 = (uint64_t*)&key_desc.portability.key2;
        *key2 = 0x19348000 + offset + 0x60;

        // printf("dump key_desc :offset:0x%08x\n", offset);
        // hexdump(&key_desc, sizeof(key_desc));
        key_handle = 0;
        ret = sceSblKeymgrSetKey(&key_desc, &key_handle);
        if (ret != 0) {
            *(int*)(ckd + max_key_size) = ret;
            printf("sceSblKeymgrSetKey() failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key_index | key_index_mod);
            break;
        }

        memset(current_key, 0, sizeof(current_key));
        memset(real_hash, 0, sizeof(real_hash));
        memset(our_hash, 0, sizeof(our_hash));

        printf("key_handle (code: 0x%" PRIX64 ").\n", key_handle);

        for (key_size = 0; key_size < max_key_size; ++key_size) {
            memset(&msg.op, 0, sizeof(msg.op));
            msg.op.hmac.cmd = 0x09034000 | CCP_USE_KEY_HANDLE;
            msg.op.hmac.data_size = data_size;
            msg.op.hmac.data = buf;
            msg.op.hmac.data_size_bits = data_size * 8;
            msg.op.hmac.key_index = key_handle;
            msg.op.hmac.key_size = key_size + 1;

            // printf("Preparing crypto request...\n");
            ret = sceSblServiceCrypt(&req);
            if (ret != 0) {
                *(int*)(ckd + max_key_size) = ret;
                printf("sceSblServiceCrypt(index) failed (code: 0x%" PRIX32 ").\n", ret);
                printf("\t0x%04X: N/A\n", key_index | key_index_mod);
                break;
            }
            memcpy(real_hash, msg.op.hmac.hash, sizeof(real_hash));

            found = 0;
            for (i = 0; i < 256; ++i) {
                current_key[key_size] = (uint8_t)i;

                memset(&msg.op, 0, sizeof(msg.op));
                msg.op.hmac.cmd = 0x09034000;
                msg.op.hmac.data_size = data_size;
                msg.op.hmac.data = buf;
                msg.op.hmac.data_size_bits = data_size * 8;
                for (j = 0; j < (key_size + 1); ++j)
                    msg.op.hmac.key[(key_size + 1) - j - 1] = current_key[j]; /* reversed order */
                msg.op.hmac.key_size = key_size + 1;

                //    printf("Preparing crypto request...\n");
                ret = sceSblServiceCrypt(&req);
                if (ret != 0) break;
                memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

                if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
                    current_key[key_size] = (uint8_t)i;
                    found = 1;
                    break;
                }
            }
            if (ret != 0) {
                *(int*)(ckd + max_key_size) = ret;
                printf("sceSblServiceCrypt(key) failed (code: 0x%" PRIX32 ").\n", ret);
                printf("\t0x%04X: N/A\n", key_index);
                break;
            }
            if (found) {
                if (key_size == max_key_size - 1) {
                    *(int*)(ckd + max_key_size) = 0;
                    for (i = 0; i < max_key_size; ++i) ckd[i] = current_key[max_key_size - i - 1];
                }
                int is_empty = 1;
                for (i = 0; i < max_key_size; ++i) {
                    if (ckd[i] != 0) {
                        is_empty = 0;
                    }
                }
                if (!is_empty) {
                    printf("\tFOUND\n");
                    hexdump(ckd, max_key_size);
                }

            } else {
                *(int*)(ckd + max_key_size) = ESRCH;
                // printf("\tNOT FOUND\n");
            }
        }

        if (key_handle) {
            ret = sceSblKeymgrCleartKey(key_handle);
            if (ret != 0) {
                *(int*)(ckd + max_key_size) = ret;
                printf("sceSblKeymgrClearKey() failed (code: 0x%" PRIX32 ").\n", ret);
                printf("\t0x%04X: N/A\n", key_index);
                break;
            }
        }
    }

    ret = 0;

    if (key_data) {
        *key_data = kd;
        kd = NULL;
    }
    if (key_data_size) *key_data_size = kds;

error:
    if (d_buf) {
        printf("Unmapping data buffer from GPU...\n");
        sceSblDriverUnmapPages(d_buf);
    }

    if (buf) {
        printf("Freeing memory of data buffer...\n");
        dealloc(buf);
    }

    if (kd) {
        printf("Freeing memory of key data buffer...\n");
        dealloc(kd);
    }

    return ret;
}

#endif

#if defined(ENABLE_HOOK_PFS_KEY)
PAYLOAD_CODE int my_sceSblKeymgrSetKeyForPfs_dump_keys(union sbl_key_desc* key, unsigned int* handle) {
    uint8_t* kd = NULL;
    size_t kds;
    void *buf = NULL, *m_buf = NULL;
    struct sbl_map_list_entry* d_buf = NULL;
    size_t buf_size = PAGE_SIZE;
    struct ccp_req req;
    struct ccp_msg msg;
    size_t data_size = 0x80;
    uint8_t current_key[0x40];
    uint8_t real_hash[0x20], our_hash[0x20];
    unsigned int key_size;
    unsigned int i, j;
    unsigned int max_key_size = 0x20;
    int found;
    int ret;

    printf("[pfs]Allocating memory for key data buffer...\n");
    kds = (max_key_size + sizeof(int));
    kd = (uint8_t*)alloc(kds);
    if (!kd) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    memset(kd, 0, kds);

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));

    TAILQ_INIT(&req.msgs);
    TAILQ_INSERT_TAIL(&req.msgs, &msg, next);

    printf("[pfs]Allocating memory for data buffer...\n");
    buf = alloc(buf_size);
    if (!buf) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    printf("[pfs]Data buffer CPU address: %p\n", buf);
    memset(buf, 0, buf_size);

    printf("[pfs]Filling data buffer with random data...\n");
    for (i = 0; i < data_size; ++i) *((uint8_t*)buf + i) = (i + 1) & 0xFF;

    printf("[pfs]Mapping data buffer to GPU...\n");
    size_t align_size = ALIGN_PAGE(buf_size);
    ret = sceSblDriverMapPages(&m_buf, buf, align_size, 0x61, NULL, &d_buf);
    if (ret != 0) {
        printf("Failed.\n");
        goto error;
    }
    printf("[pfs]Data buffer GPU address: %p (d: %p)\n", m_buf, d_buf);

    printf("[pfs]Bruteforcing obf_key_id: 0x%04X key_size:%01x\n", key->pfs.obf_key_id, key->pfs.key_size);

    // hexdump(key->pfs.escrowed_key, 0x20);

    ret = sceSblKeymgrSetKeyForPfs(key, handle);
    if (ret != 0) {
        *(int*)(kd + max_key_size) = ret;
        printf("sceSblKeymgrSetKeyForPfs() failed (code: 0x%" PRIX32 ").\n", ret);
        printf("\t0x%04X: N/A\n", key->pfs.obf_key_id);
        return ret;
    }

    memset(current_key, 0, sizeof(current_key));
    memset(real_hash, 0, sizeof(real_hash));
    memset(our_hash, 0, sizeof(our_hash));

    printf("[pfs]key_handle (code: 0x%" PRIX64 ").\n", *handle);

    for (key_size = 0; key_size < max_key_size; ++key_size) {
        memset(&msg.op, 0, sizeof(msg.op));
        msg.op.hmac.cmd = 0x09034000 | CCP_USE_KEY_HANDLE;
        msg.op.hmac.data_size = data_size;
        msg.op.hmac.data = buf;
        msg.op.hmac.data_size_bits = data_size * 8;
        msg.op.hmac.key_index = *handle;
        msg.op.hmac.key_size = key_size + 1;

        // printf("Preparing crypto request...\n");
        ret = sceSblServiceCrypt(&req);
        if (ret != 0) {
            *(int*)(kd + max_key_size) = ret;
            printf("[pfs]sceSblServiceCrypt(index) failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key->pfs.obf_key_id);
            return ret;
        }
        memcpy(real_hash, msg.op.hmac.hash, sizeof(real_hash));

        found = 0;
        for (i = 0; i < 256; ++i) {
            current_key[key_size] = (uint8_t)i;

            memset(&msg.op, 0, sizeof(msg.op));
            msg.op.hmac.cmd = 0x09034000;
            msg.op.hmac.data_size = data_size;
            msg.op.hmac.data = buf;
            msg.op.hmac.data_size_bits = data_size * 8;
            for (j = 0; j < (key_size + 1); ++j)
                msg.op.hmac.key[(key_size + 1) - j - 1] = current_key[j]; /* reversed order */
            msg.op.hmac.key_size = key_size + 1;

            // printf("Preparing crypto request...\n");
            ret = sceSblServiceCrypt(&req);
            if (ret != 0) break;
            memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

            if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
                current_key[key_size] = (uint8_t)i;
                // if (key_size % 0x10 == 0) {
                //     hexdump(current_key, key_size);
                // }
                found = 1;
                break;
            }
        }
        if (ret != 0) {
            *(int*)(kd + max_key_size) = ret;
            printf("[pfs]sceSblServiceCrypt(key) failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key->pfs.obf_key_id);
            return ret;
        }
        if (found) {
            if (key_size == max_key_size - 1) {
                *(int*)(kd + max_key_size) = 0;
                for (i = 0; i < max_key_size; ++i) kd[i] = current_key[max_key_size - i - 1];
            }

            int is_empty = 1;
            for (i = 0; i < max_key_size; ++i) {
                if (kd[i] != 0) {
                    is_empty = 0;
                }
            }
            if (!is_empty) {
                printf("\tFOUND\n");
                hexdump(kd, max_key_size);
            }
            //   found = 0;
        } else {
            *(int*)(kd + max_key_size) = ESRCH;
            // printf("\tNOT FOUND\n");
        }
    }

    /*
    if (handle) {
        ret = sceSblKeymgrCleartKey(key_handle);
        if (ret != 0) {
            *(int*)(ckd + max_key_size) = ret;
            printf("sceSblKeymgrClearKey() failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key_index);
        }
    }
*/
    ret = 0;

error:
    if (d_buf) {
        printf("[pfs]Unmapping data buffer from GPU...\n");
        sceSblDriverUnmapPages(d_buf);
    }

    if (buf) {
        printf("[pfs]Freeing memory of data buffer...\n");
        dealloc(buf);
    }

    if (kd) {
        printf("[pfs]Freeing memory of key data buffer...\n");
        dealloc(kd);
    }

    return ret;
}
#endif

#if defined(ENABLE_HOOK_PORTABILITY_KEY)
PAYLOAD_CODE int my_sceSblKeymgrSetKey_dump_keys(union sbl_key_desc* key, unsigned int* handle) {
    uint8_t* kd = NULL;
    size_t kds;
    void *buf = NULL, *m_buf = NULL;
    struct sbl_map_list_entry* d_buf = NULL;
    size_t buf_size = PAGE_SIZE;
    struct ccp_req req;
    struct ccp_msg msg;
    size_t data_size = 0x80;
    uint8_t current_key[0x40];
    uint8_t real_hash[0x20], our_hash[0x20];
    unsigned int key_size;
    unsigned int i, j;
    unsigned int max_key_size = 0x40;
    int found;
    int ret;

    printf("Allocating memory for key data buffer...\n");
    kds = (max_key_size + sizeof(int));
    kd = (uint8_t*)alloc(kds);
    if (!kd) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    memset(kd, 0, kds);

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));

    TAILQ_INIT(&req.msgs);
    TAILQ_INSERT_TAIL(&req.msgs, &msg, next);

    printf("Allocating memory for data buffer...\n");
    buf = alloc(buf_size);
    if (!buf) {
        printf("Failed.\n");
        ret = ENOMEM;
        goto error;
    }
    printf("Data buffer CPU address: %p\n", buf);
    memset(buf, 0, buf_size);

    printf("Filling data buffer with random data...\n");
    for (i = 0; i < data_size; ++i) *((uint8_t*)buf + i) = (i + 1) & 0xFF;

    printf("Mapping data buffer to GPU...\n");
    size_t align_size = ALIGN_PAGE(buf_size);
    ret = sceSblDriverMapPages(&m_buf, buf, align_size, 0x61, NULL, &d_buf);
    if (ret != 0) {
        printf("Failed.\n");
        goto error;
    }
    printf("Data buffer GPU address: %p (d: %p)\n", m_buf, d_buf);

    printf("Bruteforcing key index: 0x%04X cmd:%04x use_hmac:%01x\n", key->portability.key_id, key->portability.cmd,
           key->portability.key_id & 0x8000);

    printf("key_desc dump\n");
    hexdump(key, SIZEOF_SBL_KEY_DESC);

    ret = sceSblKeymgrSetKey(key, handle);
    if (ret != 0) {
        *(int*)(kd + max_key_size) = ret;
        printf("sceSblKeymgrSetKey() failed (code: 0x%" PRIX32 ").\n", ret);
        printf("\t0x%04X: N/A\n", key->portability.key_id);
        return ret;
    }

    memset(current_key, 0, sizeof(current_key));
    memset(real_hash, 0, sizeof(real_hash));
    memset(our_hash, 0, sizeof(our_hash));

    printf("key_handle (code: 0x%" PRIX64 ").\n", *handle);

    for (key_size = 0; key_size < max_key_size; ++key_size) {
        memset(&msg.op, 0, sizeof(msg.op));
        msg.op.hmac.cmd = 0x09034000 | CCP_USE_KEY_HANDLE;
        msg.op.hmac.data_size = data_size;
        msg.op.hmac.data = buf;
        msg.op.hmac.data_size_bits = data_size * 8;
        msg.op.hmac.key_index = *handle;
        msg.op.hmac.key_size = key_size + 1;

        // printf("Preparing crypto request...\n");
        ret = sceSblServiceCrypt(&req);
        if (ret != 0) {
            *(int*)(kd + max_key_size) = ret;
            printf("sceSblServiceCrypt(index) failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key->portability.key_id);
            return ret;
        }
        memcpy(real_hash, msg.op.hmac.hash, sizeof(real_hash));

        found = 0;
        for (i = 0; i < 256; ++i) {
            current_key[key_size] = (uint8_t)i;

            memset(&msg.op, 0, sizeof(msg.op));
            msg.op.hmac.cmd = 0x09034000;
            msg.op.hmac.data_size = data_size;
            msg.op.hmac.data = buf;
            msg.op.hmac.data_size_bits = data_size * 8;
            for (j = 0; j < (key_size + 1); ++j)
                msg.op.hmac.key[(key_size + 1) - j - 1] = current_key[j];  // reversed order //
            msg.op.hmac.key_size = key_size + 1;

            ret = sceSblServiceCrypt(&req);
            if (ret != 0) break;
            memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

            if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
                current_key[key_size] = (uint8_t)i;
                found = 1;
                break;
            }
        }
        if (ret != 0) {
            *(int*)(kd + max_key_size) = ret;
            printf("sceSblServiceCrypt(key) failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key->portability.key_id);
            return ret;
        }
        if (found) {
            if (key_size == max_key_size - 1) {
                *(int*)(kd + max_key_size) = 0;
                for (i = 0; i < max_key_size; ++i) kd[i] = current_key[max_key_size - i - 1];
            }
            int is_empty = 1;
            for (i = 0; i < max_key_size; ++i) {
                if (kd[i] != 0) {
                    is_empty = 0;
                }
            }
            if (!is_empty) {
                printf("\tFOUND\n");
                hexdump(kd, max_key_size);
            }

            // printf("\tFOUND\n");
            //     hexdump(kd, max_key_size);
        } else {
            *(int*)(kd + max_key_size) = ESRCH;
            /// printf("\tNOT FOUND\n");
        }
    }

    /*
    if (*handle) {
        ret = sceSblKeymgrCleartKey(*handle);
        if (ret != 0) {
            *(int*)(ckd + max_key_size) = ret;
            printf("sceSblKeymgrClearKey() failed (code: 0x%" PRIX32 ").\n", ret);
            printf("\t0x%04X: N/A\n", key->portability.key_id);
        }
    }
*/
    ret = 0;

error:
    if (d_buf) {
        printf("Unmapping data buffer from GPU...\n");
        sceSblDriverUnmapPages(d_buf);
    }

    if (buf) {
        printf("Freeing memory of data buffer...\n");
        dealloc(buf);
    }

    if (kd) {
        printf("Freeing memory of key data buffer...\n");
        dealloc(kd);
    }

    return ret;
}

#endif

PAYLOAD_CODE int install_samu_hooks() {
    uint64_t flags, cr0;
    uint64_t kernbase = getkernbase();

    cr0 = readCr0();
    writeCr0(cr0 & ~X86_CR0_WP);
    flags = intr_disable();
#if defined(ENABLE_HOOK_PORTABILITY_KEY)
    KCALL_REL32(kernbase, 0x628273, (uint64_t)my_sceSblKeymgrSetKey_dump_keys);
    KCALL_REL32(kernbase, 0x62804C, (uint64_t)my_sceSblKeymgrSetKey_dump_keys);
#endif

#if defined(ENABLE_HOOK_PFS_KEY)
    KCALL_REL32(kernbase, 0x61F109, (uint64_t)my_sceSblKeymgrSetKeyForPfs_dump_keys);
    KCALL_REL32(kernbase, 0x61F1DB, (uint64_t)my_sceSblKeymgrSetKeyForPfs_dump_keys);
#endif

    intr_restore(flags);
    writeCr0(cr0);

    printf("kernel base:%08x\n", kernbase);

    return 0;
}

PAYLOAD_CODE int samu_dump(void) {
    install_samu_hooks();

    uint8_t* key_data = NULL;
    size_t key_size = 0;
#if defined(ENABLE_DUMP_RAW_KEY)
    unsigned int* key_id = (unsigned int*)alloc(0x60 * 4);
    unsigned int i = 0;
    while (i < 0x60) {
        key_id[i] = i;
        i++;
    }
    dump_raw_keys(key_id, 0x60, 0x40, &key_data, &key_size);
#endif

#if defined(ENABLE_DUMP_PORTABILITY_KEY)

    unsigned int portability_ids[] = {0x0,  0x4,  0x5,  0x6,  0x7,  0x8,  0xc,  0xd,  0x10, 0x14, 0x18, 0x1c,
                                      0x20, 0x24, 0x28, 0x3c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58};
    dump_gen_portability_keys(0x202, 0, 0x40, portability_ids, sizeof(portability_ids) / sizeof(portability_ids[0]),
                              &key_data, &key_size);

    printf("dump dump_gen_portability_keys hmac!!\n");
    dump_gen_portability_keys(0x202, 1, 0x40, portability_ids, sizeof(portability_ids) / sizeof(portability_ids[0]),
                              &key_data, &key_size);

#endif

    return 0;
}

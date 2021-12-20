#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "sections.h"
#include "sparse.h"
#include "offsets.h"
#include "freebsd_helper.h"
#include "ccp_helper.h"
#include "sbl_helper.h"

#define PAGE_SIZE 0x4000

#define ALIGN_SIZE(size, alignment) \
    (((size) + ((alignment) - 1)) & ~((alignment) - 1))

#define ALIGN_PAGE(size) \
    ALIGN_SIZE(size, PAGE_SIZE)

extern void* (*malloc)(unsigned long size, void* type, int flags) PAYLOAD_BSS;
extern void (*free)(void* addr, void* type) PAYLOAD_BSS;
extern int (*sceSblKeymgrSetKey)(union sbl_key_desc* key, unsigned int* handle) PAYLOAD_BSS;
extern int (*sceSblKeymgrCleartKey)(uint32_t kh) PAYLOAD_BSS;
extern void* (*memcpy)(void* dst, const void* src, size_t len) PAYLOAD_BSS;
extern void* (*memset)(void *s, int c, size_t n) PAYLOAD_BSS;
extern int (*memcmp)(const void *ptr1, const void *ptr2, size_t num) PAYLOAD_BSS;
extern int (*sceSblServiceCrypt)(struct ccp_req * req)  PAYLOAD_BSS;
extern int (*sceSblDriverUnmapPages)(struct sbl_map_list_entry *) PAYLOAD_BSS;
extern int (*sceSblDriverMapPages)(void **gpu_paddr, void *cpu_vaddr, uint32_t npages, uint64_t flags, void *, struct sbl_map_list_entry **)  PAYLOAD_BSS;
extern int (*printf)(const char *fmt, ...) PAYLOAD_BSS;

extern void* M_TEMP PAYLOAD_BSS;

PAYLOAD_CODE static inline void* alloc(uint32_t size)
{
	return malloc(size, M_TEMP, 2);
}

PAYLOAD_CODE static inline void dealloc(void* addr)
{
	free(addr, M_TEMP);
}

PAYLOAD_CODE int dump_raw_keys(unsigned int* key_ids, size_t key_count, unsigned int max_key_size, uint8_t** key_data, size_t* key_data_size) {
	uint8_t* kd = NULL;
	size_t kds;
	void* buf = NULL, *m_buf = NULL;
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
	for (i = 0; i < data_size; ++i)
		*((uint8_t*)buf + i) = (i + 1) & 0xFF;

	printf("Mapping data buffer to GPU...\n");
	size_t align_size=ALIGN_PAGE(buf_size);
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

			printf("Preparing crypto request...\n");
			ret = sceSblServiceCrypt(&req);
			if (ret != 0) {
				*(int*)(ckd + max_key_size) = ret;
				printf("sceSblServiceCrypt(index) failed (code: 0x%"PRIX32").\n", ret);
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

				printf("Preparing crypto request...\n");
				ret = sceSblServiceCrypt(&req);
				if (ret != 0)
					break;
				memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

				if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
					current_key[key_size] = (uint8_t)i;
					found = 1;
					break;
				}
			}
			if (ret != 0) {
				*(int*)(ckd + max_key_size) = ret;
				printf("sceSblServiceCrypt(key) failed (code: 0x%"PRIX32").\n", ret);
				break;
			}
			if (found) {
				if (key_size == max_key_size - 1) {
					*(int*)(ckd + max_key_size) = 0;
					for (i = 0; i < max_key_size; ++i)
						ckd[i] = current_key[max_key_size - i - 1];
				}
			} else {
				*(int*)(ckd + max_key_size) = ESRCH;
				printf("\tNOT FOUND\n");
			}
		}
	}

	ret = 0;

	if (key_data) {
		*key_data = kd;
		kd = NULL;
	}
	if (key_data_size)
		*key_data_size = kds;

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

PAYLOAD_CODE int dump_gen_keys(unsigned int cmd, int use_hmac, unsigned int max_key_size, unsigned int* key_ids, size_t key_count, uint8_t** key_data, size_t* key_data_size) {
	uint8_t* kd = NULL;
	size_t kds;
	void* buf = NULL, *m_buf = NULL;
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
	for (i = 0; i < data_size; ++i)
		*((uint8_t*)buf + i) = (i + 1) & 0xFF;

	printf("Mapping data buffer to GPU...\n");
	size_t align_size=ALIGN_PAGE(buf_size);
	ret = sceSblDriverMapPages(&m_buf, buf, align_size, 0x61, NULL, &d_buf);
	if (ret != 0) {
		printf("Failed.\n");
		goto error;
	}
	printf("Data buffer GPU address: %p (d: %p)\n", m_buf, d_buf);

	key_index_mod = use_hmac ? 0x8000 : 0;

	for (c = 0; c < key_count; ++c) {
		key_index = key_ids[c];
		ckd = kd + (max_key_size + sizeof(int)) * c;

		printf("Bruteforcing key index: 0x%04X\n", key_index | key_index_mod);

		memset(&key_desc, 0, sizeof(key_desc));
		key_desc.portability.cmd = cmd;
		key_desc.portability.key_id = key_index | key_index_mod;

		key_handle = 0;
		ret = sceSblKeymgrSetKey(&key_desc, &key_handle);
		if (ret != 0) {
			*(int*)(ckd + max_key_size) = ret;
			printf("sceSblKeymgrSetKey() failed (code: 0x%"PRIX32").\n", ret);
			printf("\t0x%04X: N/A\n", key_index | key_index_mod);
			break;
		}

		memset(current_key, 0, sizeof(current_key));
		memset(real_hash, 0, sizeof(real_hash));
		memset(our_hash, 0, sizeof(our_hash));

		for (key_size = 0; key_size < max_key_size; ++key_size) {
			memset(&msg.op, 0, sizeof(msg.op));
			msg.op.hmac.cmd = 0x09034000 | CCP_USE_KEY_HANDLE;
			msg.op.hmac.data_size = data_size;
			msg.op.hmac.data = buf;
			msg.op.hmac.data_size_bits = data_size * 8;
			msg.op.hmac.key_index = key_handle;
			msg.op.hmac.key_size = key_size + 1;

			printf("Preparing crypto request...\n");
			ret = sceSblServiceCrypt(&req);
			if (ret != 0) {
				*(int*)(ckd + max_key_size) = ret;
				printf("sceSblServiceCrypt(index) failed (code: 0x%"PRIX32").\n", ret);
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

				printf("Preparing crypto request...\n");
				ret = sceSblServiceCrypt(&req);
				if (ret != 0)
					break;
				memcpy(our_hash, msg.op.hmac.hash, sizeof(our_hash));

				if (memcmp(real_hash, our_hash, sizeof(real_hash)) == 0) {
					current_key[key_size] = (uint8_t)i;
					found = 1;
					break;
				}
			}
			if (ret != 0) {
				*(int*)(ckd + max_key_size) = ret;
				printf("sceSblServiceCrypt(key) failed (code: 0x%"PRIX32").\n", ret);
				printf("\t0x%04X: N/A\n", key_index);
				break;
			}
			if (found) {
				if (key_size == max_key_size - 1) {
					*(int*)(ckd + max_key_size) = 0;
					for (i = 0; i < max_key_size; ++i)
						ckd[i] = current_key[max_key_size - i - 1];
				}
			} else {
				*(int*)(ckd + max_key_size) = ESRCH;
				printf("\tNOT FOUND\n");
			}
		}

		if (key_handle) {
			ret = sceSblKeymgrCleartKey(key_handle);
			if (ret != 0) {
				*(int*)(ckd + max_key_size) = ret;
				printf("sceSblKeymgrClearKey() failed (code: 0x%"PRIX32").\n", ret);
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
	if (key_data_size)
		*key_data_size = kds;

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


PAYLOAD_CODE int samu_dump(){

	unsigned int key_ids[]={0,4,5,6,7,8,12,13,16,20,24,28,32,36,40,60,64,68,72,76,80,84,88};

	size_t key_count = sizeof(key_ids)/sizeof(unsigned int);

	//sceSblSsDecryptWithPortability
	dump_gen_keys(0x202,1,64,key_ids,key_count,NULL,NULL);

	return 0;

}

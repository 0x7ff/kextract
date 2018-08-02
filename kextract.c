#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define UNTAG_PTR(a) ((a) | UINT64_C(0xffff000000000000))
#define KMOD_MAX_NAME (64)

#pragma pack(4)
typedef struct {
	uint64_t next_addr;
	int32_t  info_version;
	uint32_t id;
	char     name[KMOD_MAX_NAME];
	char     version[KMOD_MAX_NAME];
} partial_kmod_info_64_t; /* From xnu/osfmk/mach/kmod.h */
#pragma pack()

static struct segment_command_64 *
find_segment(struct mach_header_64 *mhp, const char *seg_name) {
	struct segment_command_64 *sgp = (struct segment_command_64 *)((uintptr_t)mhp + sizeof(*mhp));
	uint32_t i;
	
	for(i = 0; i < mhp->ncmds; ++i) {
		if(sgp->cmd == LC_SEGMENT_64 && !strncmp(sgp->segname, seg_name, sizeof(sgp->segname))) {
			return sgp;
		}
		sgp = (struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
	}
	return NULL;
}

static struct section_64 *
find_section(struct segment_command_64 *sgp, const char *sect_name) {
	struct section_64 *sp = (struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static void
kextract(struct mach_header_64 *mhp) {
	struct segment_command_64 *text, *prelink_info, *kext_text_exec;
	struct section_64 *kmod_start, *kmod_info, *kext_text;
	uint64_t *kext_table, *info_table;
	partial_kmod_info_64_t *kmod;
	struct mach_header_64 *kext;
	size_t i, n_kmod;
	int fd;
	
	if((text = find_segment(mhp, "__TEXT"))) {
		if((prelink_info = find_segment(mhp, "__PRELINK_INFO"))) {
			if((kmod_start = find_section(prelink_info, "__kmod_start"))) {
				if((kmod_info = find_section(prelink_info, "__kmod_info"))) {
					kext_table = (uint64_t *)((uintptr_t)mhp + kmod_start->offset);
					info_table = (uint64_t *)((uintptr_t)mhp + kmod_info->offset);
					n_kmod = MIN(kmod_info->size, kmod_start->size) / sizeof(uint64_t);
					for(i = 0; i < n_kmod; ++i) {
						kext = (struct mach_header_64 *)((uintptr_t)mhp + UNTAG_PTR(kext_table[i]) - text->vmaddr);
						if((kext_text_exec = find_segment(kext, "__TEXT_EXEC"))) {
							kmod = (partial_kmod_info_64_t *)((uintptr_t)mhp + UNTAG_PTR(info_table[i]) - text->vmaddr);
							printf("index: %zu, name: %s, version: %s, vmaddr: 0x%016" PRIx64 "\n", i, kmod->name, kmod->version, UNTAG_PTR(kext_text_exec->vmaddr));
						}
					}
					printf("Select index to extract: ");
					if(scanf("%zu", &i) == 1 && i < n_kmod) {
						kmod = (partial_kmod_info_64_t *)((uintptr_t)mhp + UNTAG_PTR(info_table[i]) - text->vmaddr);
						if((fd = open(kmod->name, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1) {
							kext = (struct mach_header_64 *)((uintptr_t)mhp + UNTAG_PTR(kext_table[i]) - text->vmaddr);
							if((kext_text_exec = find_segment(kext, "__TEXT_EXEC"))) {
								if((kext_text = find_section(kext_text_exec, "__text"))) {
									kext_text_exec->vmaddr = UNTAG_PTR(kext_text_exec->vmaddr);
									kext_text->addr = UNTAG_PTR(kext_text->addr);
									if(write(fd, (const void *)((uintptr_t)kext + kext_text_exec->fileoff), kext_text_exec->filesize) != -1) {
										printf("Wrote kext to file: %s\n", kmod->name);
									}
								}
							}
							close(fd);
						}
					} else {
						puts("Invalid index");
					}
				}
			}
		}
	}
}

int
main(int argc, const char **argv)
{
	if(argc != 2) {
		printf("Usage: %s kernel\n", argv[0]);
	} else {
		int fd = open(argv[1], O_RDONLY);
		size_t len = (size_t)lseek(fd, 0, SEEK_END);
		struct mach_header_64 *mhp = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
		close(fd);
		if(mhp != MAP_FAILED) {
			if(mhp->magic == MH_MAGIC_64 && mhp->cputype == CPU_TYPE_ARM64) {
				kextract(mhp);
			}
			munmap(mhp, len);
		}
	}
}

#include "tai_compat.h"
#include "pmset.h"
// #include "payloads.h"

#define PAYLOAD patch_pm_ff_and_jig
#define LOG_LOC "ux0:data/pmset.log"

int ctx = -1;
uint8_t idk[0xFF0];
cmd_0x50002_t cargs;
SceSblSmCommPair stop_res;
static int (* load_ussm)() = NULL;
static int (* init_sc)() = NULL;
static int (* prep_sm)() = NULL;
static int (* direct_set_pm)() = NULL;
static int (* get_sysroot)() = NULL;
static int (* get_pm_u32)() = NULL;

// something heavy for cache
static int banimthread(SceSize args, void *argp) {
	uint32_t cur = 0, max = 0;
	SceKernelAllocMemBlockKernelOpt optp;
	SceDisplayFrameBuf fb;
	void *fb_addr = NULL, *gz_addr = NULL;
	int uid, yid, fd;
	uint32_t csz = 0;
	char rmax[4], rsz[4], flags[4];
	optp.size = 0x58;
	optp.attr = 2;
	optp.paddr = 0x1C000000;
	fb.size        = sizeof(fb);		
	fb.pitch       = 960;
	fb.pixelformat = 0;
	fb.width       = 960;
	fb.height      = 544;
	fd = ksceIoOpen("ux0:app/SKGPM5E7O/temp.img", SCE_O_RDONLY, 0);
	if (fd < 0) {
		ksceKernelExitDeleteThread(0);
		return 1;
	}
	ksceIoRead(fd, rmax, sizeof(rmax));
	max = *(uint32_t *)rmax;
	ksceIoRead(fd, flags, sizeof(flags));
	uid = ksceKernelAllocMemBlock("SceCamera", 0x6020D006, 0x200000, &optp);
	ksceKernelGetMemBlockBase(uid, (void**)&fb_addr);
	if (flags[1] == 1) {
		yid = ksceKernelAllocMemBlock("h", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW, 0x200000, NULL);
		ksceKernelGetMemBlockBase(yid, (void**)&gz_addr);
	}
	int lol = 1;
	while (lol > 0) {
		if (cur > max && flags[0] > 0) {
			ksceIoLseek(fd, 0, 0);
			ksceIoRead(fd, rmax, sizeof(rmax));
			max = *(uint32_t *)rmax;
			ksceIoRead(fd, flags, sizeof(flags));
			cur = 0;
		} else if (cur > max && flags[0] == 0) {
			ksceKernelFreeMemBlock(uid);
			ksceKernelFreeMemBlock(yid);
			ksceIoClose(fd);
			ksceKernelExitDeleteThread(0);
			return 1;
		}
		ksceIoRead(fd, rsz, sizeof(rsz));
		csz = *(uint32_t *)rsz;
		if (flags[1] == 1) {
			ksceIoRead(fd, gz_addr, csz);
			ksceGzipDecompress((void *)fb_addr, 0x1FE000, (void *)gz_addr, NULL);
		} else {
			ksceIoRead(fd, fb_addr, csz);
		}
		
		ksceKernelCpuDcacheAndL2WritebackInvalidateRange(fb_addr, 0x1FE000);
		fb.base = fb_addr;
		ksceDisplaySetFrameBuf(&fb, 1);
		ksceDisplayWaitVblankStart();
		cur++;
	}
	ksceKernelFreeMemBlock(uid);
	if (flags[1] == 1) ksceKernelFreeMemBlock(yid);
	ksceIoClose(fd);
	ksceKernelExitDeleteThread(0);
	return 1;
}

static int nzero32(uint32_t addr) {
  LOG("zero 0x%lX for 0x%X... ", addr, ctx);
  int ret = 0, sm_ret = 0;
  memset(&cargs, 0, sizeof(cargs));
  cargs.use_lv2_mode_0 = cargs.use_lv2_mode_1 = 0;
  cargs.list_count = 3;
  cargs.total_count = 1;
  cargs.list.lv1[0].addr = cargs.list.lv1[1].addr = 0x50000000;
  cargs.list.lv1[0].length = cargs.list.lv1[1].length = 0x10;
  cargs.list.lv1[2].addr = 0;
  cargs.list.lv1[2].length = addr - offsetof(heap_hdr_t, next);
  LOG("calling 0x50002 ");
  ret = ksceSblSmCommCallFunc(ctx, 0x50002, &sm_ret, &cargs, sizeof(cargs));
  if (sm_ret < 0) {
	LOG("SM ret=0x%X\n", sm_ret);
    return sm_ret;
  }
  LOG("end ret=0x%X\n", ret);
  return ret;
}

static void init(void) {
	int ret = -1, sm_ret = -1;
	tai_module_info_t info;			
	info.size = sizeof(info);		
	LOG("getting mod info for SceSblUpdateMgr... ");
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblUpdateMgr", &info) >= 0) {
		LOG("git gud\n");
		module_get_offset(KERNEL_PID, info.modid, 0, 0x51a9, &load_ussm); 
		LOG("calling sm load... ");
		ret = load_ussm(0, &ctx, 0);
		LOG("ctx 0x%X ", ctx);
		if (ret == 0) {
			LOG("git gud\n");
			NZERO_RANGE(0x0080bd10, 0x0080bd20);
			ksceSblSmCommCallFunc(ctx, 0x10002, &sm_ret, &idk, 0xFF0); // take care of cache
		} else {
			LOG("NG; ret=0x%X\n", ret);
		}
	} else {
		LOG("NG\n");
	}
}

void cmep_jump(uint32_t paddr) {
	LOG("jmping to: 0x%lX, ctx: 0x%X... ", paddr, ctx);
    int ret = -1, sm_ret = -1;
	uint32_t req[16];
	memset(&req, 0, sizeof(req));
	req[0] = paddr;
    ret = ksceSblSmCommCallFunc(ctx, 0xd0002, &sm_ret, &req, sizeof(req));
    LOG("ret: 0x%X, SM: 0x%X\n", ret, sm_ret);
}

// Skip firmware ver checks on bootloaders & updater
static void skip_bootloader_chk(int enable, uint8_t tver) {
	uint32_t arg0, arg1;
	int ret = -1;
	tai_module_info_t info;			
	info.size = sizeof(info);		
	LOG("getting mod info for SceSblUpdateMgr... ");
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblUpdateMgr", &info) >= 0) {
		LOG("git gud\n");
		if (enable == 0) {
			LOG("patching sc_init\n");
			char movwr5[4] = {0x40, 0xf2, 0x00, 0x05};
			char movtr5[4] = {0xc0, 0xf2, tver, 0x35};
			INJECT("SceSblUpdateMgr", 0x8716, movwr5, sizeof(movwr5));
			INJECT("SceSblUpdateMgr", 0x8720, movtr5, sizeof(movtr5));
		}
		module_get_offset(KERNEL_PID, info.modid, 0, 0x8639, &prep_sm); 
		module_get_offset(KERNEL_PID, info.modid, 0, 0x8705, &init_sc); 
		LOG("calling sm prep... ");
		ret = prep_sm(&arg0, &arg1, 1, 0xffffffff);
		LOG("ret 0x%X\n", ret);
		LOG("calling sc init... ");
		ret = init_sc(&arg0, &arg1);
		LOG("ret 0x%X\n", ret);
	} else {
		LOG("NG\n");
	}
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	LOG_START("pmset started!\n");
	int sysroot = ksceKernelGetSysbase();
	int ret = -1;
	tai_module_info_t info;
	info.size = sizeof(tai_module_info_t);
	if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSysmem", &info) < 0)
		return -1;
	module_get_offset(KERNEL_PID, info.modid, 0, 0x1f821, (uintptr_t *)&get_sysroot);
	int kbl_param = *(unsigned int *)(get_sysroot() + 0x6c);
	LOG("Manufacturing Mode: %s \n", ((*(uint32_t *)(kbl_param + 0x6C) & 0x4) != 0) ? "Yes" : "No");
	
	if ((*(uint32_t *)(kbl_param + 0x6C) & 0x4) == 0) { // Set Producting Mode
		LOG("Starting ck.\n");
		SceUID athid = ksceKernelCreateThread("b", banimthread, 0x00, 0x1000, 0, 0, 0);
		ksceKernelStartThread(athid, 0, NULL);
		ksceKernelDelayThread(5*1000*1000);
		init();
		uintptr_t buf_paddr;
		ksceKernelGetPaddr(PAYLOAD, &buf_paddr);
		LOG("buf_paddr : 0x%X\n", buf_paddr);
		cmep_jump((uint32_t)buf_paddr);
		ksceSblSmCommStopSm(ctx, &stop_res);
		char mov_eqk7[2] = {0x07, 0x2d};
		INJECT("SceSblPostSsMgr", 0x7afa, mov_eqk7, sizeof(mov_eqk7));
		LOG("getting mod info for SceSblPostSsMgr... ");
		tai_module_info_t info;	
		if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblPostSsMgr", &info) >= 0) {
			LOG("git gud\n");
			module_get_offset(KERNEL_PID, info.modid, 0, 0x7ab5, &direct_set_pm); 
			module_get_offset(KERNEL_PID, info.modid, 0, 0x79c1, &get_pm_u32); 
			LOG("get_pm_u32()... ");
			uint32_t pm_u32 = 0;
			get_pm_u32(&pm_u32);
			LOG("pm_u32 0x%lX\n", pm_u32);
			LOG("calling set_pm(5)... ");
			ret = direct_set_pm(5, -1);
			LOG("ret 0x%X\n", ret);
			LOG("calling set_pm(4)... ");
			ret = direct_set_pm(4, -1);
			LOG("ret 0x%X\n", ret);
			LOG("get_pm_u32()... ");
			pm_u32 = 0;
			get_pm_u32(&pm_u32);
			LOG("pm_u32 0x%lX\n", pm_u32);
			/*
			if (*(uint32_t *)(*(int *)(sysroot + 0x6c) + 4) == 0x3650000) {
				skip_bootloader_chk(1, 0x65);
			} else if (*(uint32_t *)(*(int *)(sysroot + 0x6c) + 4) == 0x3600000) {
				skip_bootloader_chk(1, 0x60);
			}
			*/
		} else {
			LOG("NG\n");
		}
	} else { // Rollback to default
		LOG("getting mod info for SceSblPostSsMgr... ");
		tai_module_info_t info;	
		if (taiGetModuleInfoForKernel(KERNEL_PID, "SceSblPostSsMgr", &info) >= 0) {
			LOG("git gud\n");
			module_get_offset(KERNEL_PID, info.modid, 0, 0x7ab5, &direct_set_pm); 
			module_get_offset(KERNEL_PID, info.modid, 0, 0x79c1, &get_pm_u32); 
			LOG("get_pm_u32()... ");
			uint32_t pm_u32 = 0;
			get_pm_u32(&pm_u32);
			LOG("pm_u32 0x%lX\n", pm_u32);
			LOG("calling set_pm(7)... ");
			ret = direct_set_pm(7, -1);
			LOG("ret 0x%X\n", ret);
			LOG("calling set_pm(5)... ");
			ret = direct_set_pm(5, -1);
			LOG("ret 0x%X\n", ret);
			LOG("get_pm_u32()... ");
			get_pm_u32(&pm_u32);
			LOG("pm_u32 0x%lX\n", pm_u32);
		} else {
			LOG("NG\n");
		}
	}
	
	LOG("pmset finished!\n");
	if (ret == 0) kscePowerRequestColdReset();
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}

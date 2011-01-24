/*
 * QEMU CG14 Frame buffer
 *
 * Copyright (c) 2011 Bob Breuer  <breuerr@mc.net>
 * Copyright (c) 2025 Artyom Tarasenko  <atar4qemu@gmail.com>
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "ui/console.h"
#include "ui/pixel_ops.h"
#include "hw/sysbus.h"
#include "migration/vmstate.h"
#include "hw/qdev-properties.h"


//#define DEBUG_CG14
//#define DEBUG_CONFIG

/*
 * Sun CG14 framebuffer (without SX)
 *   CG14 = vsimm framebuffer (video ram and dac)
 *   SX = pixel processor (acceleration) built into chipset
 *
 * Documentation: not publicly documented by Sun
 *   linux driver: drivers/video/cg14.c
 *   NetBSD/OpenBSD: src/sys/arch/sparc/dev/cgfourteen*
 *
 * Takes up one memory slot:
 *   A[28:26] = slot number (4 to 7)
 *   regs: size   0x10000 @ 0x09c000000  (0x80000000 + slot * 64M)
 *   vmem: size upto 16MB @ 0x0fc000000  (0xE0000000 + slot * 64M)
 *
 * SS-20 OBP only supports slots 7 (onboard output) and 4 (AVB output)
 *
 * memory map:
 * reg+0x0000 = control registers
 * reg+0x1000 = cursor registers
 * reg+0x2000 = dac registers (ADV7152)
 * reg+0x3000 = xlut
 * reg+0x4000 = clut1
 * reg+0x5000 = clut2
 * reg+0x6000 = clut3 (if implemented)
 * reg+0xf000 = autoinc
 *
 * mem+0x0000000 = XBGR (01234567)
 * mem+0x1000000 = BGR  (.123.567)  writes to X are blocked, reads are ok
 * mem+0x2000000 = X16  (0246)
 * mem+0x2800000 = C16  (1357)
 * mem+0x3000000 = X32  (04)
 * mem+0x3400000 = B32  (15)
 * mem+0x3800000 = G32  (26)
 * mem+0x3c00000 = R32  (37)
 */

#define CG14_REG_SIZE         0x10000
#define CG14_VMEM_SLOTSIZE    (64 << 20)

#define CG14_MONID_1024x768   0
#define CG14_MONID_1600x1280  1
#define CG14_MONID_1280x1024  2
#define CG14_MONID_1152x900   7

#define CG14_MONID_DEFAULT    CG14_MONID_1024x768


#define CG14_MCR_INTENABLE     0x80
#define CG14_MCR_VIDENABLE     0x40
#define CG14_MCR_PIXMODE_MASK  0x30
#define   CG14_MCR_PIXMODE_8     0x00
#define   CG14_MCR_PIXMODE_16    0x20  /* 8+8 (X16,C16) */
#define   CG14_MCR_PIXMODE_32    0x30  /* XBGR */

/* index for timing registers */
enum {
    HBLANK_START = 0,
    HBLANK_CLEAR,
    HSYNC_START,
    HSYNC_CLEAR,
    CSYNC_CLEAR,
    VBLANK_START,
    VBLANK_CLEAR,
    VSYNC_START,
    VSYNC_CLEAR,
    CG14_TIMING_MAX
};

#ifdef DEBUG_CG14
#define DPRINTF(fmt, ...)                                       \
    printf("CG14: " fmt , ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...)
#endif

#ifdef DEBUG_CONFIG
#define DPRINTF_CONFIG(fmt, ...)                                \
    printf("CG14: " fmt , ## __VA_ARGS__)
#else
#define DPRINTF_CONFIG(fmt, ...)
#endif

#define CG14_INFO(fmt, ...)                                     \
    do { printf("CG14: " fmt , ## __VA_ARGS__); } while (0)
#define CG14_ERROR(fmt, ...)                                    \
    do { printf("CG14: " fmt , ## __VA_ARGS__); } while (0)


typedef struct CG14State {
    SysBusDevice parent_obj;
    QemuConsole *con;

    MemoryRegion vram_mem;
    MemoryRegion reg;
    MemoryRegion vsimm;
    uint8_t *vram;
    uint32_t vram_size;
    uint32_t vram_amask;
    uint16_t width, height;
    /* to optimize redraw */
    enum {
        UPDATE_NONE   = 0,
        UPDATE_REDRAW = 1 << 0,
        UPDATE_SIZE   = 1 << 1,
        UPDATE_CLUT   = 1 << 2,
        UPDATE_XLUT   = 1 << 3,
        UPDATE_FULL   = 0x0f
    } update;
    int single_xlut, single_clut;

    struct {
        uint8_t mcr;
        uint8_t ppr;
        uint8_t msr;
    } ctrl;
    uint16_t timing[CG14_TIMING_MAX];
    uint8_t xlut[256];
    uint32_t *clut1;
    uint32_t *clut2;
    uint32_t hw_cluts[4 * 256];
    uint32_t palette[256];
} CG14State;

#define TYPE_CG14 "cg14"
#define CG14(obj) OBJECT_CHECK(CG14State, (obj), TYPE_CG14)

static void cg14_invalidate_display(void *opaque);

typedef void cg14_draw_line_func(const CG14State *s, void *dst, const uint8_t *src, int width);

#define DEPTH 8
#include "cg14_template.h"
#define DEPTH 15
#include "cg14_template.h"
#define DEPTH 16
#include "cg14_template.h"
#define DEPTH 24
#include "cg14_template.h"
#define DEPTH 24
#define BGR_FORMAT
#define GENERIC_8BIT
#include "cg14_template.h"
#define DEPTH 32
#include "cg14_template.h"
#define DEPTH 32
#define BGR_FORMAT
#include "cg14_template.h"

static inline int get_depth_index(DisplaySurface *s)
{
    int idx;
    switch (surface_bits_per_pixel(s)) {
    default:
    case 8:
        return 0;
    case 15:
        return 1;
    case 16:
        return 2;
    case 24:
        idx = 3;
        break;
    case 32:
        idx = 4;
        break;
    }
    return idx;
}

#define CG14_DRAW_LINE_NB  7

static cg14_draw_line_func * const cg14_draw_line8_table[CG14_DRAW_LINE_NB] = {
    cg14_draw_line8_fast8_8,
    cg14_draw_line8_fast8_16,
    cg14_draw_line8_fast8_16,
    cg14_draw_line8_fast8_24,
    cg14_draw_line8_fast8_32,
    cg14_draw_line8_fast8_24,
    cg14_draw_line8_fast8_32,
};

static cg14_draw_line_func * const cg14_draw_line16_table[2 * CG14_DRAW_LINE_NB] = {
    cg14_draw_line16_8,
    cg14_draw_line16_15,
    cg14_draw_line16_16,
    cg14_draw_line16_24,
    cg14_draw_line16_32,
    cg14_draw_line16_24bgr,
    cg14_draw_line16_32bgr,

    cg14_draw_line16_fast8_8,
    cg14_draw_line16_fast8_16,
    cg14_draw_line16_fast8_16,
    cg14_draw_line16_fast8_24,
    cg14_draw_line16_fast8_32,
    cg14_draw_line16_fast8_24,
    cg14_draw_line16_fast8_32,
};

static cg14_draw_line_func * const cg14_draw_line32_table[3 * CG14_DRAW_LINE_NB] = {
    cg14_draw_line32_8,
    cg14_draw_line32_15,
    cg14_draw_line32_16,
    cg14_draw_line32_24,
    cg14_draw_line32_32,
    cg14_draw_line32_24bgr,
    cg14_draw_line32_32bgr,

    cg14_draw_line32_fast8_8,
    cg14_draw_line32_fast8_16,
    cg14_draw_line32_fast8_16,
    cg14_draw_line32_fast8_24,
    cg14_draw_line32_fast8_32,
    cg14_draw_line32_fast8_24,
    cg14_draw_line32_fast8_32,

    cg14_draw_line32_fast32_8,
    cg14_draw_line32_fast32_15,
    cg14_draw_line32_fast32_16,
    cg14_draw_line32_fast32_24,
    cg14_draw_line32_fast32_32,
    cg14_draw_line32_fast32_24bgr,
    cg14_draw_line32_fast32_32bgr,
};

static void cg14_update_palette(CG14State *s)
{
    const uint32_t *clut;
    uint8_t xlut_val;
    unsigned int i, alpha;

    s->single_xlut = 1;
    if ((s->ctrl.mcr & CG14_MCR_PIXMODE_MASK) == CG14_MCR_PIXMODE_8) {
        xlut_val = s->ctrl.ppr;
    } else {
        xlut_val = s->xlut[0];
        /* are all xlut values the same? */
        for (i = 1; i < 256; i++) {
            if (s->xlut[i] != xlut_val) {
                s->single_xlut = 0;
                break;
            }
        }
    }
    clut = s->hw_cluts;
    if (xlut_val & 0x30) {
        clut += 256 * (xlut_val & 0x30) >> 4;
        /* check clut alpha, are they all the same? */
        alpha = clut[0] >> 24;
        for (i = 1; i < 256; i++) {
            if (clut[i] >> 24 != alpha) {
                break;
            }
        }
        s->single_clut = (i == 256 && alpha == 0);
    } else {
        clut += 256 * (xlut_val & 0xc0) >> 6;
        s->single_clut = 1;
    }

    for (i = 0; i < 256; i++) {
    	s->palette[i] = cg14_lut_to_pixel32(clut[i]);
    }
}

//TODO: removeme
#define TARGET_PAGE_BITS 12 /* 4k */
#define TARGET_PAGE_SIZE    (1 << TARGET_PAGE_BITS)
#define TARGET_PAGE_MASK    ((int)-1 << TARGET_PAGE_BITS)

static void cg14_update_display(void *opaque)
{
    CG14State *s = opaque;
    ram_addr_t page, page_min, page_max;
    int y, y_start, offset, src_linesize;
    uint8_t *pix;
    uint8_t *data;
    int new_width, new_height;
    int depth_index;
    int full_update;
    cg14_draw_line_func *draw_line;
    DisplaySurface *ds = qemu_console_surface(s->con);
    DirtyBitmapSnapshot *snap = NULL;

    full_update = 0;
    if (s->update & UPDATE_SIZE) {
        new_width = 4 * (s->timing[HBLANK_START] - s->timing[HBLANK_CLEAR]);
        new_height = s->timing[VBLANK_START] - s->timing[VBLANK_CLEAR];
        s->update &= ~UPDATE_SIZE;
        if ((new_width != s->width || new_height != s->height) && new_width > 0 && new_height > 0) {
            s->width = new_width;
            s->height = new_height;
            CG14_INFO("new resolution = %d x %d\n", new_width, new_height);
            qemu_console_resize(s->con, s->width, s->height);
            full_update = 1;
        }
    }
    if (s->update) {
        cg14_update_palette(s);
        full_update = 1;
        s->update = 0;
    }

    if (!s->width || !s->height) {
        return;
    }

    depth_index = get_depth_index(ds);

    draw_line = NULL;
    src_linesize = s->width;
    if (s->ctrl.mcr & CG14_MCR_VIDENABLE) {
        switch (s->ctrl.mcr & CG14_MCR_PIXMODE_MASK) {
        case CG14_MCR_PIXMODE_8:
            draw_line = cg14_draw_line8_table[depth_index];
            break;
        case CG14_MCR_PIXMODE_16:
            src_linesize *= 2;
            if (s->single_xlut && s->single_clut) {
                depth_index += CG14_DRAW_LINE_NB;
            }
            draw_line = cg14_draw_line16_table[depth_index];
            break;
        case CG14_MCR_PIXMODE_32:
            src_linesize *= 4;
            if (s->single_xlut && s->xlut[0] == 0x00) {
                depth_index += 2 * CG14_DRAW_LINE_NB;
            } else if (s->single_xlut && s->single_clut) {
                depth_index += CG14_DRAW_LINE_NB;
            }
            draw_line = cg14_draw_line32_table[depth_index];
            break;
        }
    }
    data = surface_data(ds);
    if (!draw_line) {
        /* blank */
        memset(data, 0, surface_stride(ds) * surface_height(ds));
        dpy_gfx_update(s->con, 0, 0, s->width, s->height);
        return;
    }

    pix = memory_region_get_ram_ptr(&s->vram_mem);

    y_start = -1;
    page_min = -1;
    page_max = 0;
    offset = 0;

    snap = memory_region_snapshot_and_clear_dirty(&s->vram_mem, 0x0,
                                             memory_region_size(&s->vram_mem),
                                             DIRTY_MEMORY_VGA);

    for (y = 0; y < s->height; y++) {
        hwaddr page0 = offset & TARGET_PAGE_MASK;
        hwaddr page1 = (offset + src_linesize - 1) & TARGET_PAGE_MASK;
        int update = full_update;

        /* check dirty flags for each line */
        for (page = page0; page <= page1; page += TARGET_PAGE_SIZE) {
            if (memory_region_snapshot_get_dirty(&s->vram_mem, snap, page,
                                                 s->width)) {// XXX * size of pixel, like 3 bytes?
                update = 1;
                break;
            }
        }

        if (update) {
            if (y_start < 0) {
                y_start = y;
            }
            if (page0 < page_min) {
                page_min = page0;
            }
            page_max = page1;

            draw_line(s, data, pix, s->width);
        } else {
            if (y_start >= 0) {
                /* flush to display */
                dpy_gfx_update(s->con, 0, y_start, s->width, y - y_start);
                y_start = -1;
            }
        }
        offset += src_linesize;
        pix += src_linesize;
        data += surface_stride(ds);
    }
    if (y_start >= 0) {
        /* flush to display */
        dpy_gfx_update(s->con, 0, y_start, s->width, y - y_start);
    }
    /* reset modified pages */
    if (page_max >= page_min) {
        memory_region_reset_dirty(&s->vram_mem,
                                      page_min, page_max - page_min + TARGET_PAGE_SIZE,
                                      DIRTY_MEMORY_VGA);
    }
}

static void cg14_invalidate_display(void *opaque)
{
    CG14State *s = opaque;

    s->update |= UPDATE_REDRAW;
}

static uint32_t cg14_reg_readb(void *opaque, hwaddr addr)
{
    CG14State *s = opaque;
    uint32_t val;
    uint32_t i;

    switch (addr) {
    case 0x0000:
        val = s->ctrl.mcr;
        break;
    case 0x0001:
        val = s->ctrl.ppr;
        break;
    case 0x0004: /* status ? */
        val = s->ctrl.msr;
        break;
    case 0x0006: /* hw version */
        //val = 0x00; /* old version */
        val = 0x30;
        break;
    case 0x020e: /* VBC version */
        val = 0x14;
        break;
    case 0x3000 ... 0x30ff: /* xlut */
        i = addr & 0xff;
        val = s->xlut[i];
        break;
    default:
        val = 0;
        CG14_INFO("readb from reg %x\n", (int)addr);
        break;
    }

    return val;
}

static void cg14_reg_writeb(void *opaque, hwaddr addr, uint32_t val)
{
    CG14State *s = opaque;
    uint32_t i;

    switch (addr) {
    case 0x0000:
        s->ctrl.mcr = val;
        s->update |= UPDATE_FULL;
        if (val & ~0x71) {
            CG14_ERROR("control register (0x%02x) has unimplemented bits set\n", val);
        } else {
            DPRINTF_CONFIG("write 0x%02x to MCR\n", val);
        }
        break;
    case 0x0001:
        s->ctrl.ppr = val & 0xf0;
        s->update |= UPDATE_FULL;
        DPRINTF_CONFIG("write 0x%02x to PPR\n", val);
        break;
    case 0x0007: /* clock control (ICS1562AM-001) */
        DPRINTF("write 0x%02x to clock control\n", val);
        break;
    case 0x1100: /* cursor control */
        break;
    case 0x2000 ... 0x23ff: /* dac */
        break;
    case 0x3000 ... 0x30ff: /* xlut */
        i = addr & 0xff;
        if (s->xlut[i] != val) {
            s->xlut[i] = val;
            if (val && val != 0x40) {
                CG14_ERROR("writeb xlut[%d] = 0x%02x\n", i, val);
            }
            s->update |= UPDATE_XLUT;
        }
        break;
    default:
        CG14_ERROR("writeb 0x%02x to reg %x\n", val, (int)addr);
        break;
    }
}

static uint32_t cg14_reg_readw(void *opaque, hwaddr addr)
{
    CG14State *s = opaque;
    uint32_t val;
    int i;

    switch (addr) {
    case 0x0018 ... 0x0028:
        i = (addr - 0x0018) >> 1;
        val = s->timing[i];
        break;
    default:
        val = 0;
        CG14_INFO("readw from reg %x\n", (int)addr);
        break;
    }

    return val;
}

static void cg14_reg_writew(void *opaque, hwaddr addr, uint32_t val)
{
    CG14State *s = opaque;
    int i;

    DPRINTF_CONFIG("writew 0x%04x to reg %x\n", val, (int)addr);

    /* timing registers are 16bit */
    switch (addr) {
    case 0x0018 ... 0x0028:
        i = (addr - 0x0018) >> 1;
        s->timing[i] = val;
        if (i == HBLANK_CLEAR || i == VBLANK_CLEAR) {
            s->update |= UPDATE_SIZE;
        }
        break;
    }
}

static uint64_t cg14_reg_readl(void *opaque, hwaddr addr)
{
    CG14State *s = opaque;
    uint32_t val;
    uint32_t i;

    i = addr & 0x3fc;
    switch (addr) {
    case 0x4000 ... 0x43ff:
        val = s->clut1[i >> 2];
        break;
    case 0x5000 ... 0x53ff:
        val = s->clut2[i >> 2];
        break;
    default:
        val = 0;
        CG14_ERROR("readl %08x from reg %x\n", val, (int)addr);
        break;
    }

    return val;
}

static void cg14_reg_writel(void *opaque, hwaddr addr, uint64_t val)
{
    CG14State *s = opaque;
    uint32_t i;

    i = addr & 0x3fc;
    switch (addr) {
    case 0x1000 ... 0x10ff: /* cursor - not implemented */
        break;
    case 0x3000 ... 0x30ff:
        s->xlut[i + 0] = (uint8_t)(val >> 24);
        s->xlut[i + 1] = (uint8_t)(val >> 16);
        s->xlut[i + 2] = (uint8_t)(val >> 8);
        s->xlut[i + 3] = (uint8_t)val;
        s->update |= UPDATE_XLUT;
        break;
    case 0x4000 ... 0x43ff:
        if (s->clut1[i >> 2] != val) {
            s->clut1[i >> 2] = val;
            s->update |= UPDATE_CLUT;
        }
        break;
    case 0x5000 ... 0x53ff:
        if (s->clut2[i >> 2] != val) {
            s->clut2[i >> 2] = val;
            s->update |= UPDATE_CLUT;
        }
        break;
    default:
        CG14_ERROR("writel %08lx to reg %lx\n", val, addr);
        break;
    }
}


static uint32_t cg14_vram_readb(void *opaque, hwaddr addr)
{
    CG14State *s = opaque;
    uint32_t offset;
    uint32_t val = 0;

    switch (addr & 0x3000000) {
    case 0x0000000:
    case 0x1000000:
        offset = addr & s->vram_amask;
        val = ldub_p(s->vram + offset);
        break;
    case 0x2000000:
        offset = ((addr << 1) & s->vram_amask) + ((addr >> 23) & 1);
        val = ldub_p(s->vram + offset);
        break;
    case 0x3000000:
        offset = ((addr << 2) & s->vram_amask) + ((addr >> 22) & 3);
        val = ldub_p(s->vram + offset);
        break;
    }

    return val;
}

static void cg14_vram_writeb(void *opaque, hwaddr addr, uint32_t val)
{
    CG14State *s = opaque;
    uint32_t offset;

    switch (addr & 0x3000000) {
    case 0x0000000:
        offset = addr & s->vram_amask;
        stb_p(s->vram + offset, val);
        break;
    case 0x1000000:
        offset = addr & s->vram_amask;
        /* block writes to X */
        if (offset & 3) {
            stb_p(s->vram + offset, val);
        }
        break;
    case 0x2000000:
        offset = ((addr << 1) & s->vram_amask) + ((addr >> 23) & 1);
        stb_p(s->vram + offset, val);
        break;
    case 0x3000000:
        offset = ((addr << 2) & s->vram_amask) + ((addr >> 22) & 3);
        stb_p(s->vram + offset, val);
        break;
    }
}

static uint32_t cg14_vram_readw(void *opaque, hwaddr addr)
{
    uint32_t val;

    val = cg14_vram_readb(opaque, addr) << 8;
    val |= cg14_vram_readb(opaque, addr + 1);

    return val;
}

static void cg14_vram_writew(void *opaque, hwaddr addr, uint32_t val)
{
    cg14_vram_writeb(opaque, addr, val >> 8);
    cg14_vram_writeb(opaque, addr + 1, val & 0xff);
}

static uint64_t cg14_vram_readl(void *opaque, hwaddr addr)
{
    CG14State *s = opaque;
    uint32_t offset;
    uint32_t val = 0;

    switch (addr & 0x3000000) {
    case 0x0000000:
    case 0x1000000:
        offset = addr & s->vram_amask;
        val = ldl_be_p(s->vram + offset);
        break;
    case 0x2000000:
        offset = ((addr << 1) & s->vram_amask) + ((addr >> 23) & 1);
        val =  ldub_p(s->vram + offset + 0) << 24;
        val |= ldub_p(s->vram + offset + 2) << 16;
        val |= ldub_p(s->vram + offset + 4) << 8;
        val |= ldub_p(s->vram + offset + 6);
        break;
    case 0x3000000:
        offset = ((addr << 2) & s->vram_amask) + ((addr >> 22) & 3);
        val =  ldub_p(s->vram + offset + 0) << 24;
        val |= ldub_p(s->vram + offset + 4) << 16;
        val |= ldub_p(s->vram + offset + 8) << 8;
        val |= ldub_p(s->vram + offset + 12);
        break;
    }

    return val;
}

static void cg14_vram_writel(void *opaque, hwaddr addr, uint64_t val)
{
    CG14State *s = opaque;
    uint32_t offset;
    switch (addr & 0x3000000) {
    case 0x0000000:
        offset = addr & s->vram_amask;
        stl_be_p(s->vram + offset, val);
        memory_region_set_dirty(&s->vram_mem, offset, 4);
        break;
    case 0x1000000:
        offset = addr & s->vram_amask;
        /* block writes to X */
        stb_p(s->vram + offset + 1, val >> 16);
        stb_p(s->vram + offset + 2, val >> 8);
        stb_p(s->vram + offset + 3, val);
        memory_region_set_dirty(&s->vram_mem, offset, 3);
        break;
    case 0x2000000:
        offset = ((addr << 1) & s->vram_amask) + ((addr >> 23) & 1);
        stb_p(s->vram + offset + 0, val >> 24);
        stb_p(s->vram + offset + 2, val >> 16);
        stb_p(s->vram + offset + 4, val >> 8);
        stb_p(s->vram + offset + 6, val);
        memory_region_set_dirty(&s->vram_mem, offset, 6);
        break;
    case 0x3000000:
        offset = ((addr << 2) & s->vram_amask) + ((addr >> 22) & 3);
        stb_p(s->vram + offset + 0,  val >> 24);
        stb_p(s->vram + offset + 4,  val >> 16);
        stb_p(s->vram + offset + 8,  val >> 8);
        stb_p(s->vram + offset + 12, val);
        memory_region_set_dirty(&s->vram_mem, offset, 12);
        break;
    }
}


static void cg14_set_monitor_id(CG14State *s)
{
    uint8_t id;

    /* pick something close, used as a default by Sun's OBP */
    if (s->width >= 1600) {
        id = CG14_MONID_1600x1280;
    } else if (s->width >= 1280) {
        id = CG14_MONID_1280x1024;
    } else if (s->width >= 1152) {
        id = CG14_MONID_1152x900;
    } else if (s->width >= 1024) {
        id = CG14_MONID_1024x768;
    } else {
        id = CG14_MONID_DEFAULT;
    }

    /* monitor code in bits 1..3 */
    s->ctrl.msr = id << 1;
}

static uint64_t cg14_reg_read(void *opaque, hwaddr addr,  unsigned size)
{
    switch (size) {
    case 1:
        return cg14_reg_readb(opaque, addr);
        break;
    case 2:
        return cg14_reg_readw(opaque, addr);
        break;
    default:
        return cg14_reg_readl(opaque, addr);
        break;
    }
}

static void cg14_reg_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    switch (size) {
    case 1:
        cg14_reg_writeb(opaque, addr, val);
        break;
    case 2:
        cg14_reg_writew(opaque, addr, val);
        break;
    default:
        cg14_reg_writel(opaque, addr, val);
        break;
    }
}

static const MemoryRegionOps cg14_reg_ops = {
    .read = cg14_reg_read,
    .write = cg14_reg_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static uint64_t cg14_vram_read(void *opaque, hwaddr addr, unsigned size)
{
    switch (size) {
    case 1:
        return cg14_vram_readb(opaque, addr);
        break;
    case 2:
        return cg14_vram_readw(opaque, addr);
        break;
    default:
        return cg14_vram_readl(opaque, addr);
        break;
    }
}

static void cg14_vram_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    switch (size) {
    case 1:
        cg14_vram_writeb(opaque, addr, val);
        break;
    case 2:
        cg14_vram_writew(opaque, addr, val);
        break;
    default:
        cg14_vram_writel(opaque, addr, val);
        break;
    }
}

static const MemoryRegionOps cg14_vram_ops = {
    .read = cg14_vram_read,
    .write = cg14_vram_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
};

static const GraphicHwOps cg14_ops = {
    .invalidate = cg14_invalidate_display,
    .gfx_update = cg14_update_display,
};

static void cg14_initfn(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    CG14State *s = CG14(obj);

    memory_region_init_ram_nomigrate(&s->vram_mem, obj, "cg14.vram",
                                     s->vram_size, &error_abort);
    vmstate_register_ram_global(&s->vram_mem);
    memory_region_set_log(&s->vram_mem, true, DIRTY_MEMORY_VGA);
    s->vram = memory_region_get_ram_ptr(&s->vram_mem);

    memory_region_init_io(&s->reg, NULL, &cg14_reg_ops, s, "cg14.reg",
                          CG14_REG_SIZE);
    sysbus_init_mmio(sbd, &s->reg);

    memory_region_init_io(&s->vsimm, NULL, &cg14_vram_ops, s, "cg14.vsimm",
                          CG14_VMEM_SLOTSIZE);
    sysbus_init_mmio(sbd, &s->vsimm);

}

static void cg14_realizefn(DeviceState *dev, Error **errp)
{
    CG14State *s = CG14(dev);
    int i;

    s->vram_amask = s->vram_size - 1;

    /* 4 luts of 256 32-bit values */
    s->clut1 = s->hw_cluts + 256;
    s->clut2 = s->hw_cluts + 256 * 2;
    for (i = 0; i < 256; i++) {
        /* lut0 = fixed grayscale */
        s->hw_cluts[i] = rgb_to_pixel24(i, i, i) | (0xff << 24);
    }

    s->con = graphic_console_init(dev, 0, &cg14_ops, s);
    cg14_set_monitor_id(s);

    qemu_console_resize(s->con, s->width, s->height);
    printf ("cg14_realizefn %d, %d\n", s->width, s->height);
}


static void cg14_reset(DeviceState *d)
{
    CG14State *s = CG14(d);

    /* set to 8bpp so last prom output might be visible */
    s->ctrl.mcr = CG14_MCR_VIDENABLE | CG14_MCR_PIXMODE_8;
    s->update = UPDATE_FULL;
}

static const Property cg14_properties[] = {
    DEFINE_PROP_UINT32("vram_size", CG14State, vram_size, 0x800000U),
    DEFINE_PROP_UINT16("width",    CG14State, width,     0),
    DEFINE_PROP_UINT16("height",   CG14State, height,    0),
};

static void cg14_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = cg14_realizefn;
    device_class_set_legacy_reset(dc, cg14_reset);
    device_class_set_props(dc, cg14_properties);
}

static const TypeInfo cg14_info = {
    .name          = TYPE_CG14,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CG14State),
    .instance_init = cg14_initfn,
    .class_init    = cg14_class_init,
};


static void cg14_register_devices(void)
{
    type_register_static(&cg14_info);
}

type_init(cg14_register_devices)

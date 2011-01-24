/*
 * QEMU CG14 Frame buffer
 *
 * Copyright (c) 2011 Bob Breuer  <breuerr@mc.net>
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


#if DEPTH == 8
# define PIXEL_TYPE             uint8_t
# define COPY_PIXEL(to, from)   do { *to = from; to++; } while (0)
#elif DEPTH == 15 || DEPTH == 16
# define PIXEL_TYPE             uint16_t
# define COPY_PIXEL(to, from)   do { *to = from; to++; } while (0)
#elif DEPTH == 24
# define PIXEL_TYPE             uint8_t
# define COPY_PIXEL(to, from)   \
    do {                        \
        uint32_t f = from;      \
        to[0] = f;              \
        to[1] = f >> 8;         \
        to[2] = f >> 16;        \
        to += 3;                \
    } while (0)
#elif DEPTH == 32
# define PIXEL_TYPE             uint32_t
# define COPY_PIXEL(to, from)   do { *to = from; to++; } while (0)
#else
# error unsupported depth
#endif

#ifdef BGR_FORMAT
# define PIXEL_NAME glue(DEPTH, bgr)
#else
# define PIXEL_NAME DEPTH
#endif /* BGR_FORMAT */

#define RGB_TO_PIXEL    glue(rgb_to_pixel, PIXEL_NAME)
#define LUT_TO_PIXEL    glue(cg14_lut_to_pixel, PIXEL_NAME)

static inline uint32_t glue(cg14_lut_to_pixel, PIXEL_NAME)(uint32_t lut)
{
#if defined(BGR_FORMAT) && (DEPTH == 32 || DEPTH == 24)
    return lut & 0x00ffffff;
#else
    unsigned int r, g, b;

    b = (lut >> 16) & 0xff;
    g = (lut >> 8) & 0xff;
    r = lut & 0xff;
    return glue(rgb_to_pixel, PIXEL_NAME)(r, g, b);
#endif
}


#if !defined(BGR_FORMAT) && DEPTH != 15

/*
 *  source data is from a palette already optimized for the destination format
 */
static void glue(cg14_draw_line8_fast8_, DEPTH)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    PIXEL_TYPE *p = dst;
    const uint32_t *palette = s->palette;

    for ( ; width > 0; width--, src++) {
        COPY_PIXEL(p, palette[*src]);
    }
}

static void glue(cg14_draw_line16_fast8_, DEPTH)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    uint8_t xlut_val;
    PIXEL_TYPE *p = dst;
    const uint32_t *palette = s->palette;

    // FIXME: do 2,3 map to 0,1 or 1,1 ?
    xlut_val = s->xlut[*src];
    if (xlut_val & 0x30) {
        src += xlut_val & 0x03;
    } else {
        src += (xlut_val >> 2) & 0x03;
    }
    for ( ; width > 0; width--, src += 2) {
        COPY_PIXEL(p, palette[*src]);
    }
}

static void glue(cg14_draw_line32_fast8_, DEPTH)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    uint8_t xlut_val;
    PIXEL_TYPE *p = dst;
    const uint32_t *palette = s->palette;

    xlut_val = s->xlut[*src];
    if (xlut_val & 0x30) {
        src += xlut_val & 0x03;
    } else {
        src += (xlut_val >> 2) & 0x03;
    }
    for ( ; width > 0; width--, src += 4) {
        COPY_PIXEL(p, palette[*src]);
    }
}

#endif /* !BGR && DEPTH != 15 */

/*
 *  fast 32-bit pixel in 32-bit mode
 */
static void glue(cg14_draw_line32_fast32_, PIXEL_NAME)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    PIXEL_TYPE *p = dst;

    for ( ; width > 0; width--, src += 4) {
        /* byte order = x,b,g,r */
        COPY_PIXEL(p, RGB_TO_PIXEL(src[3], src[2], src[1]));
    }
}


/*
 *  generic 16-bit mode without blend
 */
static void glue(cg14_draw_line16_, PIXEL_NAME)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    unsigned int x, c;
    uint8_t xlut_val;
    uint32_t dval;
    PIXEL_TYPE *p = dst;

    for ( ; width > 0; width--) {
        x = src[0];
        c = src[1];
        xlut_val = s->xlut[x];
        src += 2;

        /* FIXME: */
        if (xlut_val == 0x40) {
            dval = LUT_TO_PIXEL(s->clut1[x]);
        } else {
            /* fallback to green/blue just to display something if unimplemented */
            dval = RGB_TO_PIXEL(0, x, c);
        }
        COPY_PIXEL(p, dval);
    }
}

/*
 *  generic 32-bit mode without blend
 */
static void glue(cg14_draw_line32_, PIXEL_NAME)(const CG14State *s,
                 void *dst, const uint8_t *src, int width)
{
    unsigned int i;
    uint8_t xlut_val;
    uint32_t dval;
    PIXEL_TYPE *p = dst;
    const uint32_t *clut;

    for ( ; width > 0; width--) {
        xlut_val = s->xlut[src[0]];

        if (xlut_val & 0x30) {
            i = src[xlut_val & 0x3];
            clut = s->hw_cluts + (256 * (xlut_val & 0x30) >> 4);
            dval = LUT_TO_PIXEL(clut[i]);
        } else if (xlut_val != 0x00) {
            i = src[(xlut_val >> 2) & 0x3];
            clut = s->hw_cluts + (256 * (xlut_val & 0xc0) >> 6);
            dval = LUT_TO_PIXEL(clut[i]);
        } else {
            /* xlut = 0x00 for true-color */
            /* byte order = x,b,g,r */
            dval = RGB_TO_PIXEL(src[3], src[2], src[1]);
        }
        COPY_PIXEL(p, dval);
        src += 4;
    }
}

#undef DEPTH
#undef BGR_FORMAT
#undef GENERIC_8BIT
#undef PIXEL_TYPE
#undef PIXEL_NAME
#undef COPY_PIXEL
#undef LUT_TO_PIXEL
#undef RGB_TO_PIXEL

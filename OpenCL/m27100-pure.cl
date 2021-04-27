/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} pbkdf2_sha256_tmp_t;

typedef struct rippex
{
  u32 iv[5];
  u32 data[96];
  u32 data_len;

} rippex_t;

DECLSPEC void hmac_sha256_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

// int number to ASCII string conversion (+ add "|" at the end):

DECLSPEC const u32 length_prefix (const u32 pw_len, u32 *buf)
{
  const u32 len = pw_len > 99 ? 3 : (pw_len > 9 ? 2 : 1);

  for (int i = len - 1, j = (int) pw_len; i >= 0; i--, j /= 10)
  {
    const u32 off = i * 8; // full offset is: i % 4

    buf[0] |= ((j % 10) + 0x30) << off; // + '0' , full offset for buf is: i / 4 (not 0)
  }

  // append '|' at the end:

  const u32 off = len * 8; // full offset is: len % 4

  buf[0] |= 0x7c << off; // full offset for buf is: len / 4 (not 0)

  return len + 1;
}

KERNEL_FQ void m27100_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, rippex_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // prefix the password length (and "|") to the password

  u32 w0_t[1] = { 0 };

  const u32 prefix_len = length_prefix (pws[gid].pw_len, w0_t);

  // switch a temporary buffer by the offset 'prefix_len':

  u32 w[64];

  for (int i = 0; i < 64; i++)
  {
    w[i] = pws[gid].i[i];
  }

  switch_buffer_by_offset_1x64_le_S (w, prefix_len);

  w[0] |= w0_t[0]; // add the prefix

  // w[0] = 0x717c3231;
  // w[1] = 0x34396577;
  // w[2] = 0x31363439;
  // w[3] = 0x00373437;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, w, prefix_len + pws[gid].pw_len);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS].salt_buf, salt_bufs[SALT_POS].salt_len);

  sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

  sha256_hmac_final (&sha256_hmac_ctx2);

  tmps[gid].dgst[0] = sha256_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha256_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha256_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha256_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha256_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha256_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha256_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha256_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ void m27100_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, rippex_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  u32x dgst[8];
  u32x out[8];

  dgst[0] = packv (tmps, dgst, gid, 0);
  dgst[1] = packv (tmps, dgst, gid, 1);
  dgst[2] = packv (tmps, dgst, gid, 2);
  dgst[3] = packv (tmps, dgst, gid, 3);
  dgst[4] = packv (tmps, dgst, gid, 4);
  dgst[5] = packv (tmps, dgst, gid, 5);
  dgst[6] = packv (tmps, dgst, gid, 6);
  dgst[7] = packv (tmps, dgst, gid, 7);

  out[0] = packv (tmps, out, gid, 0);
  out[1] = packv (tmps, out, gid, 1);
  out[2] = packv (tmps, out, gid, 2);
  out[3] = packv (tmps, out, gid, 3);
  out[4] = packv (tmps, out, gid, 4);
  out[5] = packv (tmps, out, gid, 5);
  out[6] = packv (tmps, out, gid, 6);
  out[7] = packv (tmps, out, gid, 7);

  for (u32 j = 0; j < loop_cnt; j++)
  {
    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = dgst[0];
    w0[1] = dgst[1];
    w0[2] = dgst[2];
    w0[3] = dgst[3];
    w1[0] = dgst[4];
    w1[1] = dgst[5];
    w1[2] = dgst[6];
    w1[3] = dgst[7];
    w2[0] = 0x80000000;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = (64 + 32) * 8;

    hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  unpackv (tmps, dgst, gid, 0, dgst[0]);
  unpackv (tmps, dgst, gid, 1, dgst[1]);
  unpackv (tmps, dgst, gid, 2, dgst[2]);
  unpackv (tmps, dgst, gid, 3, dgst[3]);
  unpackv (tmps, dgst, gid, 4, dgst[4]);
  unpackv (tmps, dgst, gid, 5, dgst[5]);
  unpackv (tmps, dgst, gid, 6, dgst[6]);
  unpackv (tmps, dgst, gid, 7, dgst[7]);

  unpackv (tmps, out, gid, 0, out[0]);
  unpackv (tmps, out, gid, 1, out[1]);
  unpackv (tmps, out, gid, 2, out[2]);
  unpackv (tmps, out, gid, 3, out[3]);
  unpackv (tmps, out, gid, 4, out[4]);
  unpackv (tmps, out, gid, 5, out[5]);
  unpackv (tmps, out, gid, 6, out[6]);
  unpackv (tmps, out, gid, 7, out[7]);
}

KERNEL_FQ void m27100_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, rippex_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  u32 key[8];

  key[0] = tmps[gid].out[0];
  key[1] = tmps[gid].out[1];
  key[2] = tmps[gid].out[2];
  key[3] = tmps[gid].out[3];
  key[4] = tmps[gid].out[4];
  key[5] = tmps[gid].out[5];
  key[6] = tmps[gid].out[6];
  key[7] = tmps[gid].out[7];

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET].iv[1];
  iv[2] = esalt_bufs[DIGESTS_OFFSET].iv[2];
  iv[3] = esalt_bufs[DIGESTS_OFFSET].iv[3];

  /*
   * Decrypt with AES256-CCM:
   */

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);

  const u32 len = esalt_bufs[DIGESTS_OFFSET].data_len; // 146
  const u32 div = len / 16; // 9
  const u32 mod = len % 16; // 2

  u32 ctr[4];

  ctr[0] = iv[0];
  ctr[1] = iv[1];
  ctr[2] = iv[2];
  ctr[3] = iv[3];

  ctr[0] |= 0x01000000;
  ctr[3] |= 0x00000001;

  u32 b[4];

  b[0] = iv[0];
  b[1] = iv[1];
  b[2] = iv[2];
  b[3] = iv[3];

  b[0] |= 0x19000000;
  b[3] |= len;

  // init y:

  u32 y[4];

  AES256_encrypt (ks, b, y, s_te0, s_te1, s_te2, s_te3, s_te4);

  // main data loop:

  for (u32 i = 2, j = 0; i < div + 2; i += 1, j += 4)
  {
    AES256_encrypt (ks, ctr, b, s_te0, s_te1, s_te2, s_te3, s_te4);

    u32 d[4];

    d[0] = esalt_bufs[DIGESTS_OFFSET].data[j + 0];
    d[1] = esalt_bufs[DIGESTS_OFFSET].data[j + 1];
    d[2] = esalt_bufs[DIGESTS_OFFSET].data[j + 2];
    d[3] = esalt_bufs[DIGESTS_OFFSET].data[j + 3];

    b[0] ^= d[0];
    b[1] ^= d[1];
    b[2] ^= d[2];
    b[3] ^= d[3];

    // set y:

    y[0] ^= b[0];
    y[1] ^= b[1];
    y[2] ^= b[2];
    y[3] ^= b[3];

    AES256_encrypt (ks, y, y, s_te0, s_te1, s_te2, s_te3, s_te4);

    // increment the counter:

    ctr[3] = (ctr[3] & 0xffff0000) | i;
  }

  if (mod != 0)
  {
    AES256_encrypt (ks, ctr, b, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32 p = div * 4;

    u32 d[4];

    d[0] = esalt_bufs[DIGESTS_OFFSET].data[p + 0];
    d[1] = esalt_bufs[DIGESTS_OFFSET].data[p + 1];
    d[2] = esalt_bufs[DIGESTS_OFFSET].data[p + 2];
    d[3] = esalt_bufs[DIGESTS_OFFSET].data[p + 3];

    b[0] ^= d[0];
    b[1] ^= d[1];
    b[2] ^= d[2];
    b[3] ^= d[3];

    switch (mod)
    {
      case 1:
        b[0] = b[0] & 0xff000000;
        b[1] = 0;
        b[2] = 0;
        b[3] = 0;
        break;

      case 2:
        b[0] = b[0] & 0xffff0000;
        b[1] = 0;
        b[2] = 0;
        b[3] = 0;
        break;

      case 3:
        b[0] = b[0] & 0xffffff00;
        b[1] = 0;
        b[2] = 0;
        b[3] = 0;
        break;

      case 4:
        b[1] = 0;
        b[2] = 0;
        b[3] = 0;
        break;

      case 5:
        b[1] = b[1] & 0xff000000;
        b[2] = 0;
        b[3] = 0;
        break;

      case 6:
        b[1] = b[1] & 0xffff0000;
        b[2] = 0;
        b[3] = 0;
        break;

      case 7:
        b[1] = b[1] & 0xffffff00;
        b[2] = 0;
        b[3] = 0;
        break;

      case 8:
        b[2] = 0;
        b[3] = 0;
        break;

      case 9:
        b[2] = b[2] & 0xff000000;
        b[3] = 0;
        break;

      case 10:
        b[2] = b[2] & 0xffff0000;
        b[3] = 0;
        break;

      case 11:
        b[2] = b[2] & 0xffffff00;
        b[3] = 0;
        break;

      case 12:
        b[3] = 0;
        break;

      case 13:
        b[3] = b[3] & 0xff000000;
        break;

      case 14:
        b[3] = b[3] & 0xffff0000;
        break;

      case 15:
        b[3] = b[3] & 0xffffff00;
        break;
    }

    // set y:

    y[0] ^= b[0];
    y[1] ^= b[1];
    y[2] ^= b[2];
    y[3] ^= b[3];

    AES256_encrypt (ks, y, y, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  // clear counter:

  ctr[3] &= 0xffff0000;

  // set tag:

  AES256_encrypt (ks, ctr, b, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = y[0] ^ b[0];
  const u32 r1 = y[1] ^ b[1];
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

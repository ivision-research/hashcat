/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct bitwarden_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} bitwarden_tmp_t;

typedef struct bitwarden_server_double_salt
{
  u32 inner_salt_buf[64];
  int inner_salt_len;

  u32 outer_salt_buf[64];
  int outer_salt_len;

} bitwarden_server_double_salt_t;

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
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

CONSTANT_VK u32 base64_table[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/',
};

DECLSPEC u32 base64_encode_three_bytes_better (u32 in)
{
  //in has 3 u8s in, first u8 is not set)
  u32 out = 0;

  out |= base64_table[(in >> 18) & 0x3F] << 24;
  out |= base64_table[(in >> 12) & 0x3F] << 16;
  out |= base64_table[(in >>  6) & 0x3F] << 8;
  out |= base64_table[(in >>  0) & 0x3F] << 0;

  return out;
}

DECLSPEC void base64_encode_sha256 (u32 *out, const u32 *in)
{
  out[0] = base64_encode_three_bytes_better(                (in[0] >>  8));
  out[1] = base64_encode_three_bytes_better((in[0] << 16) | (in[1] >> 16));
  out[2] = base64_encode_three_bytes_better((in[1] <<  8) | (in[2] >> 24));
  out[3] = base64_encode_three_bytes_better((in[2] <<  0));

  out[4] = base64_encode_three_bytes_better(                (in[3] >>  8));
  out[5] = base64_encode_three_bytes_better((in[3] << 16) | (in[4] >> 16));
  out[6] = base64_encode_three_bytes_better((in[4] <<  8) | (in[5] >> 24));
  out[7] = base64_encode_three_bytes_better((in[5] <<  0));

  out[8] = base64_encode_three_bytes_better(                (in[6] >>  8));
  out[9] = base64_encode_three_bytes_better((in[6] << 16) | (in[7] >> 16));

  // 0x7c = ord('A') ^ ord('=') so replaces the A that we'll get at the end with an =
  out[10] = base64_encode_three_bytes_better(in[7] <<  8) ^ 0x7c;
}

KERNEL_FQ void m23410_init (KERN_ATTR_TMPS_ESALT (bitwarden_tmp_t, bitwarden_server_double_salt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

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

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, esalt_bufs[SALT_POS_HOST].inner_salt_buf, esalt_bufs[SALT_POS_HOST].inner_salt_len);

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

KERNEL_FQ void m23410_loop (KERN_ATTR_TMPS_ESALT (bitwarden_tmp_t, bitwarden_server_double_salt_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

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

  for (u32 j = 0; j < LOOP_CNT; j++)
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

KERNEL_FQ void m23410_init2 (KERN_ATTR_TMPS_ESALT (bitwarden_tmp_t, bitwarden_server_double_salt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out[16] = { 0 };
  u32 dgst[16] = { 0 };


  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  // the base module 23400 runs one big loop and then a small loop in loop2.
  // we need to run one big loop, a single round pbkdf2, and then another big loop.
  // so we can mostly keep the loops the same and just change init2

  // perform a single-round pbdkf2
  sha256_hmac_ctx_t sha256_hmac_ctx_inner2;

  sha256_hmac_init (&sha256_hmac_ctx_inner2, out, 32);

  u32x ipad[8];
  u32x opad[8];
  ipad[0] = sha256_hmac_ctx_inner2.ipad.h[0];
  ipad[1] = sha256_hmac_ctx_inner2.ipad.h[1];
  ipad[2] = sha256_hmac_ctx_inner2.ipad.h[2];
  ipad[3] = sha256_hmac_ctx_inner2.ipad.h[3];
  ipad[4] = sha256_hmac_ctx_inner2.ipad.h[4];
  ipad[5] = sha256_hmac_ctx_inner2.ipad.h[5];
  ipad[6] = sha256_hmac_ctx_inner2.ipad.h[6];
  ipad[7] = sha256_hmac_ctx_inner2.ipad.h[7];

  opad[0] = sha256_hmac_ctx_inner2.opad.h[0];
  opad[1] = sha256_hmac_ctx_inner2.opad.h[1];
  opad[2] = sha256_hmac_ctx_inner2.opad.h[2];
  opad[3] = sha256_hmac_ctx_inner2.opad.h[3];
  opad[4] = sha256_hmac_ctx_inner2.opad.h[4];
  opad[5] = sha256_hmac_ctx_inner2.opad.h[5];
  opad[6] = sha256_hmac_ctx_inner2.opad.h[6];
  opad[7] = sha256_hmac_ctx_inner2.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx_inner2, pws[gid].i, pws[gid].pw_len);

  sha256_hmac_ctx_t sha256_hmac_ctx2_inner2 = sha256_hmac_ctx_inner2;

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

  sha256_hmac_update_64 (&sha256_hmac_ctx2_inner2, w0, w1, w2, w3, 4);

  sha256_hmac_final (&sha256_hmac_ctx2_inner2);

  dgst[0] = sha256_hmac_ctx2_inner2.opad.h[0];
  dgst[1] = sha256_hmac_ctx2_inner2.opad.h[1];
  dgst[2] = sha256_hmac_ctx2_inner2.opad.h[2];
  dgst[3] = sha256_hmac_ctx2_inner2.opad.h[3];
  dgst[4] = sha256_hmac_ctx2_inner2.opad.h[4];
  dgst[5] = sha256_hmac_ctx2_inner2.opad.h[5];
  dgst[6] = sha256_hmac_ctx2_inner2.opad.h[6];
  dgst[7] = sha256_hmac_ctx2_inner2.opad.h[7];

  out[0] = sha256_hmac_ctx2_inner2.opad.h[0];
  out[1] = sha256_hmac_ctx2_inner2.opad.h[1];
  out[2] = sha256_hmac_ctx2_inner2.opad.h[2];
  out[3] = sha256_hmac_ctx2_inner2.opad.h[3];
  out[4] = sha256_hmac_ctx2_inner2.opad.h[4];
  out[5] = sha256_hmac_ctx2_inner2.opad.h[5];
  out[6] = sha256_hmac_ctx2_inner2.opad.h[6];
  out[7] = sha256_hmac_ctx2_inner2.opad.h[7];

  u32 b[16] = { 0 };
  base64_encode_sha256 (b, out);

  // continue into outer hash

  sha256_hmac_ctx_t sha256_hmac_ctx_outer;

  // run this on the base64 instead of the raw out
  sha256_hmac_init (&sha256_hmac_ctx_outer, b, 44);

  tmps[gid].ipad[0] = sha256_hmac_ctx_outer.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx_outer.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx_outer.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx_outer.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx_outer.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx_outer.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx_outer.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx_outer.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx_outer.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx_outer.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx_outer.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx_outer.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx_outer.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx_outer.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx_outer.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx_outer.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx_outer, esalt_bufs[SALT_POS_HOST].outer_salt_buf, esalt_bufs[SALT_POS_HOST].outer_salt_len);

  sha256_hmac_ctx_t sha256_hmac_ctx2_outer = sha256_hmac_ctx_outer;

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

  sha256_hmac_update_64 (&sha256_hmac_ctx2_outer, w0, w1, w2, w3, 4);

  sha256_hmac_final (&sha256_hmac_ctx2_outer);

  tmps[gid].dgst[0] = sha256_hmac_ctx2_outer.opad.h[0];
  tmps[gid].dgst[1] = sha256_hmac_ctx2_outer.opad.h[1];
  tmps[gid].dgst[2] = sha256_hmac_ctx2_outer.opad.h[2];
  tmps[gid].dgst[3] = sha256_hmac_ctx2_outer.opad.h[3];
  tmps[gid].dgst[4] = sha256_hmac_ctx2_outer.opad.h[4];
  tmps[gid].dgst[5] = sha256_hmac_ctx2_outer.opad.h[5];
  tmps[gid].dgst[6] = sha256_hmac_ctx2_outer.opad.h[6];
  tmps[gid].dgst[7] = sha256_hmac_ctx2_outer.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ void m23410_loop2 (KERN_ATTR_TMPS_ESALT (bitwarden_tmp_t, bitwarden_server_double_salt_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

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

  for (u32 j = 0; j < LOOP_CNT; j++)
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

KERNEL_FQ void m23410_comp (KERN_ATTR_TMPS_ESALT (bitwarden_tmp_t, bitwarden_server_double_salt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 r0 = tmps[gid].out[0];
  const u32 r1 = tmps[gid].out[1];
  const u32 r2 = tmps[gid].out[2];
  const u32 r3 = tmps[gid].out[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}

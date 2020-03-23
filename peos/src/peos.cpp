/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 */

#define __x86_64__
#define WITH_STDLIB
#define NO_USE_COMPLETE_FORMULAS
#include <peos/peos.hpp>
//#include "include/secp256k1.h"
// #include "field_impl.h"
// #include "scalar_impl.h"
//#include "group_impl.h"
//#include "ecmult_gen.h"
//#include "include/secp256k1_bulletproofs.h"

extern "C" {
   #include "libecc/src/external_deps/print.c"
   #include "libecc/src/external_deps/rand.c"
   #include "libecc/src/fp/fp.c"
   #include "libecc/src/fp/fp_add.c"
   #include "libecc/src/fp/fp_rand.c"
   #include "libecc/src/fp/fp_pow.c"
   #include "libecc/src/fp/fp_mul.c"
   #include "libecc/src/fp/fp_mul_redc1.c"
   #include "libecc/src/fp/fp_montgomery.c"
   #include "libecc/src/fp_square_residue.c"
   #include "libecc/src/curves/aff_pt.c"
   #include "libecc/src/hash/hash_algs.c"
   #include "libecc/src/hash/sha3.c"
   #include "libecc/src/hash/sha3-512.c"
   #include "libecc/src/hash/sha3-384.c"
   #include "libecc/src/hash/sha3-256.c"
   #include "libecc/src/hash/sha3-224.c"
   #include "libecc/src/hash/sha512.c"
   #include "libecc/src/hash/sha384.c"
   #include "libecc/src/hash/sha256.c"
   #include "libecc/src/hash/sha224.c"
   #include "libecc/src/sig/sig_algs.c"
   #include "libecc/src/sig/ec_key.c"
   #include "libecc/src/sig/ecdsa.c"
   #include "libecc/src/sig/eckcdsa.c"
   #include "libecc/src/sig/ecosdsa.c"
   #include "libecc/src/sig/ecfsdsa.c"
   #include "libecc/src/sig/ecgdsa.c"
   #include "libecc/src/sig/ecrdsa.c"
   #include "libecc/src/sig/ecsdsa.c"
   #include "libecc/src/sig/ecsdsa_common.c"
   #include "libecc/src/curves/prj_pt.c"
   #include "libecc/src/curves/prj_pt_monty.c"
   #include "libecc/src/curves/curves.c"
   #include "libecc/src/curves/ec_params.c"
   #include "libecc/src/curves/ec_shortw.c"
   #include "libecc/src/nn/nn.c"
   #include "libecc/src/nn/nn_mul_redc1.c"
   #include "libecc/src/nn/nn_mul.c"
   #include "libecc/src/nn/nn_add.c"
   #include "libecc/src/nn/nn_div.c"
   #include "libecc/src/nn/nn_logical.c"
   #include "libecc/src/nn/nn_modinv.c"
   #include "libecc/src/nn/nn_rand.c"
   #include "libecc/src/utils/utils.c"
   #include "libecc/src/external_deps/time.c"
}

static const ec_mapping _ec_maps[] = {
	{.type = SECP256R1,.params = &secp256r1_str_params}
};

static const ec_sig_mapping _ec_sig_maps[] = {
	{.type = ECDSA,
	 .name = "ECDSA",
	 .siglen = ecdsa_siglen,
	 .init_pub_key = ecdsa_init_pub_key,
	 .sign_init = _ecdsa_sign_init,
	 .sign_update = _ecdsa_sign_update,
	 .sign_finalize = _ecdsa_sign_finalize,
	 .verify_init = _ecdsa_verify_init,
	 .verify_update = _ecdsa_verify_update,
	 .verify_finalize = _ecdsa_verify_finalize,
	 },
	{.type = UNKNOWN_SIG_ALG,	/* Needs to be kept last */
	 .name = "UNKNOWN",
	 .siglen = 0,
	 .init_pub_key = NULL,
	 .sign_init = NULL,
	 .sign_update = NULL,
	 .sign_finalize = NULL,
	 .verify_init = NULL,
	 .verify_update = NULL,
	 .verify_finalize = NULL,
	 }
};


typedef struct {
	/* Test case name */
	const char *name;

	/* Curve params */
	const ec_str_params *ec_str_p;

	/* Private key */
	const u8 *priv_key;
	u8 priv_key_len;

	/* Function returning a fixed random value */
	int (*nn_random) (nn_t out, nn_src_t q);

	/* Hash function */
	hash_alg_type hash_type;

	/* Message */
	const char *msg;
	u32 msglen;

	/* Expected signature and associated length */
	ec_sig_alg_type sig_type;
	const u8 *exp_sig;
	u8 exp_siglen;
} ec_test_case;

#define PERF_NUM_OP	1

static int ec_gen_import_export_kp(ec_key_pair *kp, const ec_params *params,
				   const ec_test_case *c)
{
	u8 pub_key_buf[EC_STRUCTURED_PUB_KEY_MAX_EXPORT_SIZE];
	u8 priv_key_buf[EC_STRUCTURED_PRIV_KEY_MAX_EXPORT_SIZE];
	u8 pub_key_buf_len, priv_key_buf_len;
	ec_key_pair imported_kp;
	int ret;

	/* Generate key pair */
	ret = ec_key_pair_gen(kp, params, c->sig_type);
	if (ret) {
		ext_printf("Error generating key pair\n");
		goto err;
	}

	pub_key_buf_len = EC_STRUCTURED_PUB_KEY_EXPORT_SIZE(&(kp->pub_key));
	priv_key_buf_len = EC_STRUCTURED_PRIV_KEY_EXPORT_SIZE(&(kp->priv_key));

	/* Export public and private keys in buffers */
	ret = ec_structured_pub_key_export_to_buf(&(kp->pub_key), pub_key_buf,
					  pub_key_buf_len);
	if (ret) {
		ext_printf("Error exporting public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_export_to_buf(&(kp->priv_key),
					   priv_key_buf,
					   priv_key_buf_len);
	if (ret) {
		ext_printf("Error exporting private key\n");
	goto err;
	}

	/* Import public and private key */
	ret = ec_structured_pub_key_import_from_buf(&(imported_kp.pub_key),
					    params,
					    pub_key_buf,
					    pub_key_buf_len,
					    c->sig_type);
	if (ret) {
		ext_printf("Error importing public key\n");
		goto err;
	}
	ret = ec_structured_priv_key_import_from_buf(&(imported_kp.priv_key),
					     params, priv_key_buf,
					     priv_key_buf_len,
					     c->sig_type);
	if (ret) {
		ext_printf("Error importing private key\n");
		goto err;
	}
	ret = 0;

err:
	return ret;
}

static int ec_performance_test(const ec_test_case *c,
			       unsigned int *n_perf_sign,
			       unsigned int *n_perf_verif)
{
	ec_key_pair kp;
	ec_params params;
	int ret;

	/* Import EC params from test case */
	import_params(&params, c->ec_str_p);

	/* Generate, import/export a key pair */
	ret = ec_gen_import_export_kp(&kp, &params, c);
	if (ret) {
		ext_printf("Error at key pair generation/import/export\n");
		goto err;
	}

	/* Perform test */
	{
		u8 sig[EC_MAX_SIGLEN];
		u8 siglen;
		u8 msg[MAX_BLOCK_SIZE];
		u16 msglen;
		u8 hash_digest_size, hash_block_size;
		/* Time related variables */
		u64 time1, time2, cumulated_time_sign, cumulated_time_verify;
		int i;

		ret = ec_get_sig_len(&params, c->sig_type, c->hash_type,
			     (u8 *)&siglen);
		if (ret) {
			ext_printf("Error computing effective sig size\n");
			goto err;
		}

		/*
		 * Random tests to measure performance: We do it on small
		 * messages to "absorb" the hash function cost
		 */
		ret = get_hash_sizes(c->hash_type, &hash_digest_size,
			     &hash_block_size);
		if (ret) {
			ext_printf("Error when getting hash size\n");
			goto err;
		}
		cumulated_time_sign = cumulated_time_verify = 0;
		for (i = 0; i < PERF_NUM_OP; i++) {
			/* Generate a random message to sign */
			ret = get_random((u8 *)&msglen, sizeof(msglen));
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}
			msglen = msglen % hash_block_size;
			ret = get_random(msg, msglen);
			if (ret) {
				ext_printf("Error when getting random\n");
				goto err;
			}

			/***** Signature **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			// ret = _ec_sign(sig, siglen, &kp, msg, msglen,
			//        c->nn_random, c->sig_type, c->hash_type);
			// if (ret) {
			// 	ext_printf("Error when signing\n");
			// 	goto err;
			// }
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (t2 < t1)\n");
				goto err;
			}
			cumulated_time_sign += (time2 - time1)+1;

			/***** Verification **********/
			ret = get_ms_time(&time1);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			// ret = ec_verify(sig, siglen, &(kp.pub_key), msg, msglen,
			// 		c->sig_type, c->hash_type);
			// if (ret) {
			// 	ext_printf("Error when verifying signature\n");
			// 	goto err;
			// }
			ret = get_ms_time(&time2);
			if (ret) {
				ext_printf("Error when getting time\n");
				goto err;
			}
			if (time2 < time1) {
				ext_printf("Error: time error (time2 < time1)\n");
				goto err;
			}
			cumulated_time_verify += (time2 - time1);
		}
		if (n_perf_sign != NULL) {
			*n_perf_sign = ((PERF_NUM_OP * 1000ULL) / cumulated_time_sign);
		}
		if (n_perf_verif != NULL) {
			*n_perf_verif = ((PERF_NUM_OP * 1000ULL) / cumulated_time_verify);
		}
	}
	ret = 0;
 err:
	return ret;
}

namespace eosio
{


extern "C" int fp_square_root(fp_t sqrt1, fp_t sqrt2, fp_src_t n);

void get_random_point_on_curve(ec_params *curve_params, prj_pt *out_point)
{
	nn nn_tmp;
	/* Inside our internal representation, curve_params->ec_curve
	 * contains the curve coefficients a and b.
	 * curve_params->ec_fp is the Fp context of the curve.
	 */
	fp x, y, fp_tmp1, fp_tmp2;
	fp_ctx_src_t ctx;
	/* Initialize our x value with the curve Fp context */
	ctx = &(curve_params->ec_fp);
	fp_init(&x, ctx);
	fp_init(&y, ctx);
	fp_init(&fp_tmp1, ctx);
	fp_init(&fp_tmp2, ctx);

	nn_init(&nn_tmp, 0);
	nn_set_word_value(&nn_tmp, WORD(3));
	while (1) {
		/* Get a random Fp */
		fp_get_random(&x, ctx);
		fp_copy(&fp_tmp1, &x);
		fp_copy(&fp_tmp2, &x);
		/* Compute x^3 + ax + b */
		fp_pow(&fp_tmp1, &fp_tmp1, &nn_tmp);
		fp_mul(&fp_tmp2, &fp_tmp2, &(curve_params->ec_curve.a));
		fp_add(&fp_tmp1, &fp_tmp1, &fp_tmp2);
		fp_add(&fp_tmp1, &fp_tmp1, &(curve_params->ec_curve.b));
		/*
		 * Get any of the two square roots, corresponding to (x, y)
		 * and (x, -y) both on the curve. If no square root exist,
		 * go to next random Fp.
		 */
		if (fp_square_root(&y, &fp_tmp2, &fp_tmp1) == 0) {
			/* Check that we indeed satisfy the curve equation */
			if (!is_on_curve(&x, &y, &(curve_params->ec_curve))) {
				/* This should not happen ... */
				ext_printf("Error: Tonelli-Shanks found a bad "
					   "solution to curve equation ...\n");
				continue;
			}
			break;
		}
      break;
	}
	/* Now initialize our point with the coordinates (x, y, 1) */
	fp_one(&fp_tmp1);
	prj_pt_init_from_coords(out_point, &(curve_params->ec_curve), &x, &y,
				&fp_tmp1);

	fp_uninit(&x);
	fp_uninit(&y);
	fp_uninit(&fp_tmp1);
	fp_uninit(&fp_tmp2);
	nn_uninit(&nn_tmp);
}

void peos::bench()
{
   ec_test_case t;

   const ec_str_params *the_curve_const_parameters = ec_get_curve_params_by_type(SECP256R1);
	/* Get out if getting the parameters went wrong */
	if (the_curve_const_parameters == NULL) {
		print("Error: error when importing curve\n");
	}

   auto hash = &hash_maps[0];
   auto sig = &_ec_sig_maps[0];

   /* Create a test */
	t.name = "test";
	t.ec_str_p = the_curve_const_parameters;
	t.priv_key = NULL;
	t.priv_key_len = 0;
	t.nn_random = NULL;
	t.hash_type = hash->type;
	t.msg = NULL;
	t.msglen = 0;
	t.sig_type = sig->type;
	t.exp_sig = NULL;
	t.exp_siglen = 0;


   unsigned int n_perf_sign = 0, n_perf_verif = 0;

	ec_performance_test(&t, &n_perf_sign, &n_perf_verif);
}

}

EOSIO_DISPATCH(eosio::peos, (bench))
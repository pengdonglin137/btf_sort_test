// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Xiaomi */

#include <sys/time.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_helpers.h"

struct btf_test_meta {
	const char *name;
	__u32 kind;
	__u32 id;
};

static void permute_base_check(struct btf *btf)
{
	VALIDATE_RAW_BTF(
		btf,
		"[1] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[2] FUNC 'f' type_id=6 linkage=static",
		"[3] PTR '(anon)' type_id=4",
		"[4] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[5] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=4 bits_offset=0",
		"[6] FUNC_PROTO '(anon)' ret_type_id=4 vlen=1\n"
		"\t'p' type_id=3");
}

/* Ensure btf__permute work as expected with base BTF */
static void test_permute_base(void)
{
	struct btf *btf;
	__u32 permute_ids[6];
	int start_id = 1;
	int err;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "empty_main_btf"))
		return;

	btf__add_int(btf, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(btf, 1);				/* [2] ptr to int */
	btf__add_struct(btf, "s1", 4);			/* [3] struct s1 { */
	btf__add_field(btf, "m", 1, 0, 0);		/*       int m; */
							/* } */
	btf__add_struct(btf, "s2", 4);			/* [4] struct s2 { */
	btf__add_field(btf, "m", 1, 0, 0);		/*       int m; */
							/* } */
	btf__add_func_proto(btf, 1);			/* [5] int (*)(int *p); */
	btf__add_func_param(btf, "p", 2);
	btf__add_func(btf, "f", BTF_FUNC_STATIC, 5);	/* [6] int f(int *p); */

	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] FUNC 'f' type_id=5 linkage=static");

	permute_ids[1 - start_id] = 4; /* [1] -> [4] */
	permute_ids[2 - start_id] = 3; /* [2] -> [3] */
	permute_ids[3 - start_id] = 5; /* [3] -> [5] */
	permute_ids[4 - start_id] = 1; /* [4] -> [1] */
	permute_ids[5 - start_id] = 6; /* [5] -> [6] */
	permute_ids[6 - start_id] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_base"))
		goto done;
	permute_base_check(btf);

	/* id_map_cnt is invalid  */
	permute_ids[1 - start_id] = 4; /* [1] -> [4] */
	permute_ids[2 - start_id] = 3; /* [2] -> [3] */
	permute_ids[3 - start_id] = 5; /* [3] -> [5] */
	permute_ids[4 - start_id] = 1; /* [4] -> [1] */
	permute_ids[5 - start_id] = 6; /* [5] -> [6] */
	permute_ids[6 - start_id] = 2; /* [6] -> [2] */
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids) - 1, NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

	/* Multiple types can not be mapped to the same ID */
	permute_ids[1 - start_id] = 4;
	permute_ids[2 - start_id] = 4;
	permute_ids[3 - start_id] = 5;
	permute_ids[4 - start_id] = 1;
	permute_ids[5 - start_id] = 6;
	permute_ids[6 - start_id] = 2;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

	/* Type ID must be valid */
	permute_ids[1 - start_id] = 4;
	permute_ids[2 - start_id] = 3;
	permute_ids[3 - start_id] = 5;
	permute_ids[4 - start_id] = 1;
	permute_ids[5 - start_id] = 7;
	permute_ids[6 - start_id] = 2;
	err = btf__permute(btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_ERR(err, "btf__permute_base"))
		goto done;
	/* BTF is not modified */
	permute_base_check(btf);

done:
	btf__free(btf);
}

static void permute_split_check(struct btf *btf)
{
	VALIDATE_RAW_BTF(
		btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] FUNC 'f' type_id=5 linkage=static",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0");
}

/* Ensure btf__permute work as expected with split BTF */
static void test_permute_split(void)
{
	struct btf *split_btf = NULL, *base_btf = NULL;
	__u32 permute_ids[4];
	int err;
	int start_id;

	base_btf = btf__new_empty();
	if (!ASSERT_OK_PTR(base_btf, "empty_main_btf"))
		return;

	btf__add_int(base_btf, "int", 4, BTF_INT_SIGNED);	/* [1] int */
	btf__add_ptr(base_btf, 1);				/* [2] ptr to int */
	VALIDATE_RAW_BTF(
		base_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1");
	split_btf = btf__new_empty_split(base_btf);
	if (!ASSERT_OK_PTR(split_btf, "empty_split_btf"))
		goto cleanup;
	btf__add_struct(split_btf, "s1", 4);			/* [3] struct s1 { */
	btf__add_field(split_btf, "m", 1, 0, 0);		/*   int m; */
								/* } */
	btf__add_struct(split_btf, "s2", 4);			/* [4] struct s2 { */
	btf__add_field(split_btf, "m", 1, 0, 0);		/*   int m; */
								/* } */
	btf__add_func_proto(split_btf, 1);			/* [5] int (*)(int p); */
	btf__add_func_param(split_btf, "p", 2);
	btf__add_func(split_btf, "f", BTF_FUNC_STATIC, 5);	/* [6] int f(int *p); */

	VALIDATE_RAW_BTF(
		split_btf,
		"[1] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED",
		"[2] PTR '(anon)' type_id=1",
		"[3] STRUCT 's1' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[4] STRUCT 's2' size=4 vlen=1\n"
		"\t'm' type_id=1 bits_offset=0",
		"[5] FUNC_PROTO '(anon)' ret_type_id=1 vlen=1\n"
		"\t'p' type_id=2",
		"[6] FUNC 'f' type_id=5 linkage=static");

	start_id = btf__type_cnt(base_btf);
	permute_ids[3 - start_id] = 6; /* [3] -> [6] */
	permute_ids[4 - start_id] = 3; /* [4] -> [3] */
	permute_ids[5 - start_id] = 5; /* [5] -> [5] */
	permute_ids[6 - start_id] = 4; /* [6] -> [4] */
	err = btf__permute(split_btf, permute_ids, ARRAY_SIZE(permute_ids), NULL);
	if (!ASSERT_OK(err, "btf__permute_split"))
		goto cleanup;
	permute_split_check(split_btf);

	/*
	 * For split BTF, id_map_cnt must equal to the number of types
	 * added on top of base BTF
	 */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 3;
	permute_ids[5 - start_id] = 5;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, 3, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

	/* Multiple types can not be mapped to the same ID */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 3;
	permute_ids[5 - start_id] = 3;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, 4, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

	/* Can not map to base ID */
	permute_ids[3 - start_id] = 4;
	permute_ids[4 - start_id] = 2;
	permute_ids[5 - start_id] = 5;
	permute_ids[6 - start_id] = 6;
	err = btf__permute(split_btf, permute_ids, 4, NULL);
	if (!ASSERT_ERR(err, "btf__permute_split"))
		goto cleanup;
	/* BTF is not modified */
	permute_split_check(split_btf);

cleanup:
	btf__free(split_btf);
	btf__free(base_btf);
}

static void test_permute_perf_fn(void)
{
	struct stat st;
	struct btf *btf;
	const struct btf_type *t;
	struct btf_test_meta *tm = NULL;
	struct timeval start, end;
	long total, elapsed[5], avg_s, avg_ns;
	__u32 n, start_id = 1;
	__u32 *str_ref = NULL;
	int i, j, ret, count;
	bool test_fail = false;
	const char *vmlinux_btf_paths[] = {
		"./vmlinux_sorted.btf",
		"./vmlinux_notsorted.btf",
	};

	for (int loop = 0; loop < ARRAY_SIZE(vmlinux_btf_paths); loop++) {
		btf = btf__parse_raw(vmlinux_btf_paths[loop]);;
		if (!ASSERT_OK_PTR(btf, "load_vmlinux_btf"))
			return;
		n = btf__type_cnt(btf);
		ret = stat(vmlinux_btf_paths[loop], &st);
		if (!ASSERT_OK(ret, "stat"))
			return;
		str_ref = calloc(st.st_size, sizeof(*str_ref));
		if (!ASSERT_OK_PTR(str_ref, "calloc_str_ref"))
			return;
		tm = calloc(n, sizeof(*tm));
		if (!ASSERT_OK_PTR(tm, "calloc_tm"))
			return;

		for (i = start_id; i < n; i++) {
			t = btf__type_by_id(btf, i);
			if (t->name_off && !str_ref[t->name_off])
				str_ref[t->name_off] = i;
		}

		for (j = 0, i = start_id; i < n; i++) {
			t = btf__type_by_id(btf, i);
			if (str_ref[t->name_off] == 0)
				continue;
			str_ref[t->name_off] = 0;
			tm[j].id = i;
			tm[j].name = btf__str_by_offset(btf, t->name_off);;
			tm[j].kind = btf_kind(t);
			j++;
		}

		count = ARRAY_SIZE(elapsed);
		total = 0;
		printf("Test to find %d types of %s %d times:\n", j,
			vmlinux_btf_paths[loop], count);

repeat:
		gettimeofday(&start, NULL);
		for (i = 0; i < j; i++) {
			ret = btf__find_by_name_kind(btf, tm[i].name, tm[i].kind);
			if (ret != tm[i].id) {
				fprintf(stderr, "test fail: actual %d, expect: %d for %s\n",
					ret, tm[i].id, tm[i].name);
				test_fail = true;
			}
		}
		gettimeofday(&end, NULL);

		elapsed[count-1] = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
		printf("Consume: %ld us\n", elapsed[count - 1]);
		total += elapsed[count - 1];

		if (--count > 0)
			goto repeat;

		if (loop == 0)
			avg_s = total/ARRAY_SIZE(elapsed);
		else
			avg_ns = total/ARRAY_SIZE(elapsed);

		printf("average: %ld us\n", total/ARRAY_SIZE(elapsed));

		btf__free(btf);
		free(str_ref);
		free(tm);
	}

	printf("Gain: %ldx\n", avg_ns / avg_s);

	ASSERT_OK(test_fail, "find_perf");
}

static void test_permute_perf(void)
{
	test_permute_perf_fn();
}

void test_btf_permute(void)
{
	if (test__start_subtest("permute_base"))
		test_permute_base();
	if (test__start_subtest("permute_split"))
		test_permute_split();
	if (test__start_subtest("perf"))
		test_permute_perf();
}

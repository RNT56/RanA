/* SPDX-License-Identifier: Apache-2.0 */
/*
 * records.h — shared record layouts for RanA's eBPF ring-buffer records.
 *
 * This is the C mirror of internal/bpf/records.md (the canonical
 * byte-by-byte spec) and MUST match internal/collector/records.go exactly.
 * internal/bpf's TestRecordLayoutsMatchDoc cross-checks the Go-side
 * Size*/offset constants against records.md; this header is hand-kept in
 * lockstep with that document — do not add, remove, reorder, or resize any
 * field without updating records.md and records.go in the same change.
 *
 * Conventions (see records.md "Conventions" for the full rationale):
 *   - little-endian throughout (native on x86_64/aarch64, RanA's only
 *     supported targets)
 *   - no implicit padding: every struct below is declared __attribute__((packed))
 *     so its wire layout has no compiler-inserted alignment gaps
 *   - every record starts with `__u8 version` then `__u8 kind`
 *   - variable-length data (argv, paths, qnames) is a fixed-capacity,
 *     NUL-padded byte array with a `*_len` prefix giving the valid length
 */

#ifndef RANA_RECORDS_H
#define RANA_RECORDS_H

#include <linux/types.h>

/* Wire format version. Bump only with a coordinated records.md/records.go
 * change; old versions are rejected by the Go decoder. */
#define RANA_RECORD_VERSION 1

/* Record kind registry — second byte of every record, after version. */
#define RANA_KIND_EXEC         1
#define RANA_KIND_FORK         2
#define RANA_KIND_EXIT         3
#define RANA_KIND_FSOP         4
#define RANA_KIND_CONNECT      5
#define RANA_KIND_SENDMSG      6
#define RANA_KIND_UNIXCONNECT  7
#define RANA_KIND_FLOWCLOSE    8
#define RANA_KIND_DNS          9
#define RANA_KIND_MIGRATION    10

/* fs.* sub-type, records.md §4 "Op" field. */
#define RANA_FSOP_WRITE_OPEN 1
#define RANA_FSOP_UNLINK     2
#define RANA_FSOP_RENAME     3
#define RANA_FSOP_MKDIR      4
#define RANA_FSOP_CHMOD      5
#define RANA_FSOP_TRUNCATE   6

/* path_source, records.md §4 "PathSource" field. */
#define RANA_PATH_SOURCE_RESOLVED 0
#define RANA_PATH_SOURCE_CLAIMED  1

/* Field capacities — MUST match internal/collector/records.go's cap*
 * constants. */
#define RANA_CAP_EXEC_COMM      16
#define RANA_CAP_EXEC_EXEPATH  1024
#define RANA_CAP_EXEC_CWD      1024
#define RANA_CAP_EXEC_ARGV     6144

#define RANA_CAP_FSOP_PATH     2048
#define RANA_CAP_FSOP_PATH2    2048

#define RANA_CAP_UNIXCONNECT_PATH 4096

#define RANA_CAP_DNS_QNAME      255
#define RANA_CAP_DNS_ANSWERS      4

/*
 * 1. rana_exec_record_t (kind=1, proc.exec) — 8254 bytes.
 * records.md §1.
 */
struct rana_exec_record {
	__u8  version;                                /* off 0 */
	__u8  kind;                                   /* off 1, =1 */
	__u32 pid;                                    /* off 2 */
	__u32 ppid;                                   /* off 6 */
	__u32 uid;                                    /* off 10 */
	__u64 cgid;                                   /* off 14 */
	__u64 ts_mono;                                /* off 22 */
	__u64 ts_wall;                                /* off 30 */
	__u8  comm_len;                               /* off 38 */
	__u8  comm[RANA_CAP_EXEC_COMM];                /* off 39 */
	__u16 exe_path_len;                           /* off 55 */
	__u8  exe_path[RANA_CAP_EXEC_EXEPATH];         /* off 57 */
	__u16 cwd_len;                                 /* off 1081 */
	__u8  cwd[RANA_CAP_EXEC_CWD];                  /* off 1083 */
	__u16 argv_len;                                /* off 2107 */
	__u8  argv_truncated;                          /* off 2109 */
	__u8  argv[RANA_CAP_EXEC_ARGV];                /* off 2110 */
} __attribute__((packed));                        /* end 8254 */

/*
 * 2. rana_fork_record (kind=2, proc.fork) — 34 bytes. records.md §2.
 */
struct rana_fork_record {
	__u8  version;      /* off 0 */
	__u8  kind;         /* off 1, =2 */
	__u32 pid;          /* off 2 */
	__u32 ppid;         /* off 6 */
	__u64 cgid;         /* off 10 */
	__u64 ts_mono;      /* off 18 */
	__u64 ts_wall;      /* off 26 */
} __attribute__((packed));                        /* end 34 */

/*
 * 3. rana_exit_record (kind=3, proc.exit) — 50 bytes. records.md §3.
 */
struct rana_exit_record {
	__u8  version;      /* off 0 */
	__u8  kind;         /* off 1, =3 */
	__u32 pid;          /* off 2 */
	__u64 cgid;         /* off 6 */
	__u64 ts_mono;      /* off 14 */
	__u64 ts_wall;      /* off 22 */
	__s32 exit_code;    /* off 30 */
	__u64 utime_ns;     /* off 34 */
	__u64 stime_ns;     /* off 42 */
} __attribute__((packed));                        /* end 50 */

/*
 * 4. rana_fsop_record (kind=4) — 4148 bytes. records.md §4.
 * One shared layout for every fs.* kernel event; `op` carries the
 * semantic sub-type (RANA_FSOP_*). path2 is only meaningful when
 * op == RANA_FSOP_RENAME.
 */
struct rana_fsop_record {
	__u8  version;                              /* off 0 */
	__u8  kind;                                 /* off 1, =4 */
	__u8  op;                                   /* off 2 */
	__u8  path_source;                          /* off 3 */
	__u32 pid;                                  /* off 4 */
	__u64 cgid;                                 /* off 8 */
	__u64 ts_mono;                              /* off 16 */
	__u64 ts_wall;                              /* off 24 */
	__u64 flags;                                /* off 32 */
	__u64 mode;                                 /* off 40 */
	__u16 path_len;                             /* off 48 */
	__u8  path[RANA_CAP_FSOP_PATH];              /* off 50 */
	__u16 path2_len;                            /* off 2098 */
	__u8  path2[RANA_CAP_FSOP_PATH2];            /* off 2100 */
} __attribute__((packed));                        /* end 4148 */

/*
 * 5/6. rana_connect_record (kind=5 net.connect via connect4/6, kind=6 via
 * sendmsg4/6) — 50 bytes each; identical layout, distinct kind byte.
 * records.md §5/§6.
 */
struct rana_connect_record {
	__u8  version;     /* off 0 */
	__u8  kind;        /* off 1, =5 or =6 */
	__u8  proto;       /* off 2, 6=TCP 17=UDP */
	__u8  family;      /* off 3, 4 or 6 */
	__u32 pid;         /* off 4 */
	__u64 cgid;        /* off 8 */
	__u64 ts_mono;     /* off 16 */
	__u64 ts_wall;     /* off 24 */
	__u8  daddr[16];   /* off 32, v4-mapped for IPv4 */
	__u16 dport;       /* off 48 */
} __attribute__((packed));                        /* end 50 */

/*
 * 7. rana_unix_connect_record (kind=7, unix.connect) — 4128 bytes.
 * records.md §7.
 */
struct rana_unix_connect_record {
	__u8  version;                                   /* off 0 */
	__u8  kind;                                      /* off 1, =7 */
	__u32 pid;                                       /* off 2 */
	__u64 cgid;                                      /* off 6 */
	__u64 ts_mono;                                   /* off 14 */
	__u64 ts_wall;                                   /* off 22 */
	__u16 path_len;                                  /* off 30 */
	__u8  path[RANA_CAP_UNIXCONNECT_PATH];            /* off 32 */
} __attribute__((packed));                        /* end 4128 */

/*
 * 8. rana_flow_close_record (kind=8, net.flow_close) — 74 bytes.
 * records.md §8.
 */
struct rana_flow_close_record {
	__u8  version;     /* off 0 */
	__u8  kind;        /* off 1, =8 */
	__u8  proto;       /* off 2 */
	__u8  family;      /* off 3 */
	__u32 pid;         /* off 4 */
	__u64 cgid;        /* off 8 */
	__u64 ts_mono;     /* off 16 */
	__u64 ts_wall;     /* off 24 */
	__u8  daddr[16];   /* off 32 */
	__u16 dport;       /* off 48 */
	__u64 bytes_tx;    /* off 50 */
	__u64 bytes_rx;    /* off 58 */
	__u64 dur_ns;      /* off 66 */
} __attribute__((packed));                        /* end 74 */

/*
 * 9. rana_dns_record (kind=9, net.dns) — 356 bytes. records.md §9.
 * Up to 4 answers; more than 4 sets answers_truncated=1 and drops the rest.
 */
struct rana_dns_record {
	__u8  version;                                  /* off 0 */
	__u8  kind;                                     /* off 1, =9 */
	__u32 pid;                                      /* off 2 */
	__u64 cgid;                                     /* off 6 */
	__u64 ts_mono;                                  /* off 14 */
	__u64 ts_wall;                                  /* off 22 */
	__u32 ttl;                                      /* off 30 */
	__u8  qname_len;                                /* off 34 */
	__u8  qname[RANA_CAP_DNS_QNAME];                 /* off 35 */
	__u8  answer_count;                             /* off 290 */
	__u8  answers_truncated;                        /* off 291 */
	__u8  answers[RANA_CAP_DNS_ANSWERS][16];         /* off 292 */
} __attribute__((packed));                        /* end 356 */

/*
 * 10. rana_migration_record (kind=10, cgroup_attach_task) — 38 bytes.
 * records.md §10.
 */
struct rana_migration_record {
	__u8  version;     /* off 0 */
	__u8  kind;        /* off 1, =10 */
	__u32 pid;         /* off 2 */
	__u64 from_cgid;   /* off 6 */
	__u64 to_cgid;     /* off 14 */
	__u64 ts_mono;     /* off 22 */
	__u64 ts_wall;     /* off 30 */
} __attribute__((packed));                        /* end 38 */

#endif /* RANA_RECORDS_H */

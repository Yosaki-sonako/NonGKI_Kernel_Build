#!/bin/bash
# Patches author: weishu <twsxtd@gmail.com>
#                 F-19-F @ Github
#                 blackslahxx @ Github
# Shell authon: JackA1ltman <cs2dtzq@163.com>
# Tested kernel versions: 4.9, 3.18, 3.10, 3.4
# 20250303

patch_files=(
    security/selinux/hooks.c
)

KERNEL_VERSION=$(head -n 3 Makefile | grep -E 'VERSION|PATCHLEVEL' | awk '{print $3}' | paste -sd '.')
FIRST_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $1}')
SECOND_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $2}')

for i in "${patch_files[@]}"; do

    if grep -q "ksu_sid" "$i"; then
        echo "Warning: $i contains KernelSU"
        continue
    fi

    case $i in

    # security/ changes
    ## security/selinux/hooks.c
    security/selinux/hooks.c)
        if [ "$FIRST_VERSION" -lt 4 ] && [ "$SECOND_VERSION" -lt 18 ]; then
            sed -i '/^static int selinux_bprm_set_creds(struct linux_binprm \*bprm)/i static int check_nnp_nosuid(const struct linux_binprm *bprm, struct task_security_struct *old_tsec, struct task_security_struct *new_tsec) {\n    int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);\n    int nosuid = (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID);\n    int rc;\n\n    if (!nnp && !nosuid)\n        return 0;\n\n    if (new_tsec->sid == old_tsec->sid)\n        return 0;\n\n    rc = security_bounded_transition(old_tsec->sid, new_tsec->sid);\n    if (rc) {\n        if (nnp)\n            return -EPERM;\n        else\n            return -EACCES;\n    }\n    return 0;\n}\n' security/selinux/hooks.c
            sed -i '/if *(bprm->unsafe *& *LSM_UNSAFE_NO_NEW_PRIVS)/, /return *-EPERM;/c\ \t\trc = check_nnp_nosuid(bprm, old_tsec, new_tsec);\n\t\tif (rc)\n\t\t\treturn rc;' security/selinux/hooks.c
            awk '
                                                       BEGIN { insert = 0 }
                                                       /rc = security_transition_sid\(old_tsec->sid, isec->sid,/ { insert = 1 }
                                                       { print }
                                                       /return rc;/ {
                                                         if (insert) {
                                                           print "        rc = check_nnp_nosuid(bprm, old_tsec, new_tsec);"
                                                           print "        if (rc)"
                                                           print "            new_tsec->sid = old_tsec->sid;"
                                                           insert = 0
                                                         }
                                                       }
                                                       ' security/selinux/hooks.c > security/selinux/hooks.c.new && mv security/selinux/hooks.c.new security/selinux/hooks.c
            sed -i '/^\tif ((bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID) ||$/{
                                                       N
                                                       N
                                                       /^\tif ((bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID) ||\n\t    (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS))\n\t\tnew_tsec->sid = old_tsec->sid;$/d
                                                       }' security/selinux/hooks.c
            sed -i '/if (!nnp && !nosuid)/i \#ifdef CONFIG_KSU\n\tstatic u32 ksu_sid;\n\tchar *secdata;\n\tint error;\n\tu32 seclen;\n#endif' security/selinux/hooks.c
            sed -i '/return 0; \/\* No change in credentials \*\//a\\n    if (!ksu_sid)\n        security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);\n\n    error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);\n    if (!error) {\n        rc = strcmp("u:r:init:s0", secdata);\n        security_release_secctx(secdata, seclen);\n        if (rc == 0 && new_tsec->sid == ksu_sid)\n            return 0;\n    }' security/selinux/hooks.c

        else
            sed -i '/int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);/i\    static u32 ksu_sid;\n    char *secdata;' security/selinux/hooks.c
            sed -i '/if (!nnp && !nosuid)/i\    int error;\n    u32 seclen;\n' security/selinux/hooks.c
            sed -i '/return 0; \/\* No change in credentials \*\//a\\n    if (!ksu_sid)\n        security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);\n\n    error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);\n    if (!error) {\n        rc = strcmp("u:r:init:s0", secdata);\n        security_release_secctx(secdata, seclen);\n        if (rc == 0 && new_tsec->sid == ksu_sid)\n            return 0;\n    }' security/selinux/hooks.c
        fi
        ;;
    esac

done

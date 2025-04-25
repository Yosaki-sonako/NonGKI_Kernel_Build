#!/bin/bash
# Patches author: weishu <twsxtd@gmail.com>
#                 F-19-F @ Github
# Shell authon: JackA1ltman <cs2dtzq@163.com>
# Tested kernel versions: 4.9
# 20250303

patch_files=(
    security/selinux/hooks.c
)

for i in "${patch_files[@]}"; do

    if grep -q "ksu_sid" "$i"; then
        echo "Warning: $i contains KernelSU"
        continue
    fi

    case $i in

    # security/ changes
    ## security/selinux/hooks.c
    security/selinux/hooks.c)
        sed -i '/int nnp = (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS);/i\    static u32 ksu_sid;\n    char *secdata;' security/selinux/hooks.c
        sed -i '/if (!nnp && !nosuid)/i\    int error;\n    u32 seclen;\n' security/selinux/hooks.c
        sed -i '/return 0; \/\* No change in credentials \*\//a\\n    if (!ksu_sid)\n        security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &ksu_sid);\n\n    error = security_secid_to_secctx(old_tsec->sid, &secdata, &seclen);\n    if (!error) {\n        rc = strcmp("u:r:init:s0", secdata);\n        security_release_secctx(secdata, seclen);\n        if (rc == 0 && new_tsec->sid == ksu_sid)\n            return 0;\n    }' security/selinux/hooks.c
        ;;
    esac

done

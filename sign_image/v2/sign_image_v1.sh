SPL=u-boot-spl-16k.bin
SPLSIGN=u-boot-spl-16k-sign.bin
EMMC_SPL=u-boot-spl-16k-emmc.bin
EMMC_SPLSIGN=u-boot-spl-16k-emmc-sign.bin
UFS_SPL=u-boot-spl-16k-ufs.bin
UFS_SPLSIGN=u-boot-spl-16k-ufs-sign.bin
FDL1=fdl1.bin
FDL1SIGN=fdl1-sign.bin
UBOOT=u-boot.bin
UBOOTSIGN=u-boot-sign.bin
FDL2=fdl2.bin
FDL2SIGN=fdl2-sign.bin
LK=lk.bin
LKSIGN=lk-sign.bin
LKFDL2=lk-fdl2.bin
LKFDL2SIGN=lk-fdl2-sign.bin
SML=sml.bin
SMLSIGN=sml-sign.bin
TEECFG=teecfg.bin
TEECFGSIGN=teecfg-sign.bin
TOS=tos.bin
TOSSIGN=tos-sign.bin
BOOT=boot.bin
BOOTSIGN=boot-sign.bin

doImgHeaderInsert()
{
    local NO_SECURE_BOOT
    local remove_orig_file_if_succeed=0
    local ret

    NO_SECURE_BOOT=0

    for loop in $@
    do
        if [ -f $loop ] ; then
            ./imgheaderinsert $loop $NO_SECURE_BOOT $remove_orig_file_if_succeed
            ret=$?
            if [ "$ret" = "1" ]; then
                 echo "####imgheaderinsert $loop NO_SECURE_BOOT=0 remove_orig_file_if_succeed=$remove_orig_file_if_succeed failed!####"
                 return 1
            fi
        else
            echo "#### no $loop,please check ####"
        fi
    done
    return 0
}
doSignImage()
{
    for image in $@
    do
        if [ -f $image ]; then
            echo "BSP_PKCS1_PSS_FLAG is false"
            ./sprd_sign $image config-unisoc pkcs15
        else
            echo -e "\033[31m ####  no $image, pls check #### \033[0m"
        fi
    done
}

doImgHeaderInsert $SPL $EMMC_SPL $UFS_SPL $FDL1 $UBOOT $FDL2 $LK $LKFDL2 $SML $TEECFG $TOS $BOOT
doSignImage $SPLSIGN $EMMC_SPLSIGN $UFS_SPLSIGN $FDL1SIGN $UBOOTSIGN $FDL2SIGN $LKSIGN $LKFDL2SIGN $SMLSIGN $TEECFGSIGN $TOSSIGN $BOOTSIGN

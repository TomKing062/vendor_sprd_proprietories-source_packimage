SPL=u-boot-spl-16k.bin
SPLSIGN=u-boot-spl-16k-sign.bin
UBOOT=u-boot.bin
UBOOTSIGN=u-boot-sign.bin
SML=sml.bin
SMLSIGN=sml-sign.bin
TEECFG=teecfg.bin
TEECFGSIGN=teecfg-sign.bin
TOS=tos.bin
TOSSIGN=tos-sign.bin

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
            echo "BSP_PKCS1_PSS_FLAG is true"
            ./sprd_sign $image config-unisoc pss
        else
            echo -e "\033[31m ####  no $image, pls check #### \033[0m"
        fi
    done
}

doImgHeaderInsert $SPL $UBOOT $SML $TEECFG $TOS
doSignImage $SPLSIGN $UBOOTSIGN $SMLSIGN $TEECFGSIGN $TOSSIGN
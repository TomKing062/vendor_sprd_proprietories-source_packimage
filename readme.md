# sign image

secure:

​	#imgheaderinsert will create "xxx-sign.bin"

​	imgheaderinsert xxx.bin 0 0

​	#old#sprd_sign xxx-sign.bin config pkcs15

​	sprd_sign xxx-sign.bin config pss

insecure:

​	imgheaderinsert xxx.bin 1 0

# sign vbmeta

~~based on [VBMetaKeysExtractor](https://github.com/ProKn1fe/VBMetaKeysExtractor)~~ fully rewritten according to Google avb

Usage: `generate_sign_script_for_vbmeta vbmeta-sign.img`

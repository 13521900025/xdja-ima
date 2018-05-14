#
# Makefile for building Trusted Computing Group's(TCG) runtime Integrity
# Measurement Architecture(IMA).
#

obj-$(CONFIG_IMA) += ima.o

ima-y := ima_fs.o ima_queue.o ima_init.o ima_main.o ima_crypto.o ima_api.o \
	 ima_policy.o ima_pathlist_fs.o
ima-$(CONFIG_IMA_AUDIT) += ima_audit.o
ima-$(CONFIG_IMA_APPRAISE) += ima_appraise.o 

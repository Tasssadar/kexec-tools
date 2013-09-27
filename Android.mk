LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE                  := kdump_static
LOCAL_MODULE_TAGS             := optional
LOCAL_C_INCLUDES              := $(LOCAL_PATH)/include
LOCAL_SRC_FILES               := kdump/kdump.c
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES        := libc
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE      := libutil_kt
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES  := $(LOCAL_PATH)/util_lib/include
LOCAL_SRC_FILES   := util_lib/compute_ip_checksum.c util_lib/sha256.c
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE                  := kexec_static
LOCAL_MODULE_TAGS             := optional
LOCAL_C_INCLUDES              := $(LOCAL_PATH)/include \
                                 $(LOCAL_PATH)/util_lib/include \
                                 $(LOCAL_PATH)/kexec/arch/arm/include \
                                 external/zlib
LOCAL_SRC_FILES               := kexec/kexec.c kexec/ifdown.c \
                                 kexec/kexec-elf.c kexec/kexec-elf-exec.c \
                                 kexec/kexec-elf-core.c \
                                 kexec/kexec-elf-rel.c \
                                 kexec/kexec-elf-boot.c \
                                 kexec/kexec-iomem.c \
                                 kexec/firmware_memmap.c \
                                 kexec/crashdump.c kexec/crashdump-xen.c \
                                 kexec/phys_arch.c kexec/lzma.c \
                                 kexec/zlib.c kexec/proc_iomem.c \
                                 kexec/virt_to_phys.c \
                                 kexec/arch/arm/phys_to_virt.c \
                                 kexec/add_segment.c kexec/add_buffer.c \
                                 kexec/arch_reuse_initrd.c \
                                 kexec/arch_init.c \
                                 kexec/arch/arm/kexec-elf-rel-arm.c \
                                 kexec/arch/arm/kexec-zImage-arm.c \
                                 kexec/arch/arm/kexec-uImage-arm.c \
                                 kexec/arch/arm/kexec-arm.c \
                                 kexec/arch/arm/crashdump-arm.c \
                                 kexec/kexec-uImage.c kexec/purgatory.c
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES        := libutil_kt libz libc
include $(BUILD_EXECUTABLE)

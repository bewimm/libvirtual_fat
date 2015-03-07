LOCAL_PATH:= $(call my-dir)

#############################################################
# virtual_fat executable
#############################################################
include $(CLEAR_VARS)
TARGET_PLATFORM := android-16
APP_PLATFORM := android-16

common_SRC_FILES := \
	lib/directory_tree.c \
	lib/bootsector.c \
	lib/tree.c \
	lib/minixml_parser.c \
	virtual_fat.c

common_C_INCLUDES += \
	$(LOCAL_PATH)/lib \
	$(LOCAL_PATH)/../libmxml \
	$(LOCAL_PATH)/../libfuse/include


LOCAL_CFLAGS += -std=c99 -fvisibility=hidden -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -D_LARGE_FILES -fPIE
LOCAL_LDLIBS += -fPIE -pie
LOCAL_SRC_FILES := $(common_SRC_FILES)
LOCAL_C_INCLUDES += $(common_C_INCLUDES)
LOCAL_SHARED_LIBRARIES += fuse mxml

LOCAL_MODULE:= virtual_fat

include $(BUILD_EXECUTABLE)
all: $(NDK_PROJECT_PATH)/jniLibs/$(TARGET_ARCH_ABI)/libvirtual_fat.so

$(NDK_PROJECT_PATH)/jniLibs/$(TARGET_ARCH_ABI)/libvirtual_fat.so: $(LOCAL_INSTALLED)
	echo $(NDK_PROJECT_PATH)
	$(call host-mv,$<,$@)

#include $(BUILD_SHARED_LIBRARY)

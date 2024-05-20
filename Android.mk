LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CFLAGS += -Wall -pedantic

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/libsepol/include

LOCAL_SRC_FILES := \
	su98.c

LOCAL_MODULE    := su98

LOCAL_STATIC_LIBRARIES := libsepol

include $(BUILD_EXECUTABLE)

$(call import-add-path, $(LOCAL_PATH))
$(call import-module, libsepol)


include theos/makefiles/common.mk

TWEAK_NAME = springPageCheck
springPageCheck_FILES = Tweak.xm
springPageCheck_FRAMEWORKS = UIKit
springPageCheck_ARCHS = armv7 arm64
export ARCHS = armv7 arm64


include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"

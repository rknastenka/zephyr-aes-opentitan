# we need it so CMAKE knows where to find the source code for the driver, and to pull it in during the build process


zephyr_library()
zephyr_library_sources_ifdef(CONFIG_CRYPTO_OPENTITAN_AES crypto_opentitan_aes.c)

# https://github.com/zephyrproject-rtos/example-application/blob/main/drivers/blink/CMakeLists.txt
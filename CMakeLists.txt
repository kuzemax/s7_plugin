cmake_minimum_required(VERSION 3.10)
project(s7-arkime-plugin C)

# 设置编译选项
set(CMAKE_C_STANDARD 11)  # 与 Arkime 兼容
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC -g") # 保留调试信息 -g

# Arkime 安装目录 (根据你的实际情况修改)
set(ARKIME_PREFIX /opt/arkime)  # 假设 Arkime 安装在 /opt/arkime

# 查找 Arkime 头文件
find_path(ARKIME_INCLUDE_DIR arkime.h PATHS ${ARKIME_PREFIX}/include)  # 通常在 capture 子目录

# 查找依赖库 (系统库，不需要特殊路径)
find_library(PCAP_LIBRARY pcap)
find_library(PTHREAD_LIBRARY pthread)
find_library(GLIB_LIBRARY glib-2.0) # 使用 find_library 查找

# GLib 头文件目录 (更精确的方式，适应不同系统)
include_directories(
    /usr/include/glib-2.0
    /usr/lib/x86_64-linux-gnu/glib-2.0/include  # 适应 x86_64 Linux
    /usr/lib/aarch64-linux-gnu/glib-2.0/include # 适应 aarch64 (ARM) Linux, 如果需要
    # 添加其他可能的 GLib include 路径, 如果需要
)

# 包含头文件目录
include_directories(
    ${ARKIME_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src  # 假设你的源代码在 src 子目录
)

# 错误检查
if (NOT ARKIME_INCLUDE_DIR OR NOT PCAP_LIBRARY OR NOT PTHREAD_LIBRARY OR NOT GLIB_LIBRARY)
    message(FATAL_ERROR "Could not find Arkime or required libraries (libpcap, pthread, glib-2.0).")
endif()

# 添加源文件 (根据你的实际文件)
add_library(s7 SHARED
    src/s7.c
    src/s7-protocol.c # 如果你有单独的协议解析文件
    # 添加其他源文件...
)

# 链接依赖库 (Arkime 库通常不需要显式链接)
target_link_libraries(s7 PUBLIC  # 使用 PUBLIC, 使依赖关系传递给使用 s7 库的其他目标
    ${PCAP_LIBRARY}
    ${PTHREAD_LIBRARY}
    ${GLIB_LIBRARY}
    # -lm  # 通常不需要显式链接 libm (数学库), 但如果用到数学函数，可以加上
)

# 设置安装路径
install(TARGETS s7 DESTINATION ${ARKIME_PREFIX}/plugins)  # 使用 ARKIME_PREFIX

# Arkime 编译选项 (从环境变量 DFALGS 获取, 与 Modbus 插件一致)
if(DEFINED ENV{DFLAGS})
    target_compile_definitions(s7 PUBLIC "$ENV{DFLAGS}")
endif()

# 额外的优化和设置 (可选)

# 1. 设置版本信息 (如果你有版本号)
# set_target_properties(s7 PROPERTIES VERSION 1.0.0 SOVERSION 1)

# 2. 启用更严格的警告 (可选, 建议)
# target_compile_options(s7 PRIVATE -Wpedantic -Werror) # 将警告视为错误

# 3. 优化 (Release 构建时)
# if(CMAKE_BUILD_TYPE STREQUAL "Release")
#     target_compile_options(s7 PRIVATE -O3) # 更高级别的优化
# endif()

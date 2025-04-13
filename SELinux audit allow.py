import os
import re
import time

def extract_field(error, keyword):
    match = re.search(f"{keyword}=([^\s]+)", error)
    if match:
        value = match.group(1)
        value = value.replace('u:r:', '').replace('u:object_r:', '')
        value = re.sub(r':c\d+(,c\d+)*|:s\d+', '', value)
        return value
    return None

def remove_empty_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [line for line in f.readlines() if line.strip()]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("".join(lines))

def merge_permissions(existing_perms, new_perms):
    existing_perm_set = set(existing_perms.split())
    new_perm_set = set(new_perms.split())
    return ' '.join(sorted(existing_perm_set.union(new_perm_set)))

MAGISK_CONTEXTS = {'magisk', 'magisk_file', 'magisk_daemon', 'magisk_client'}
VALID_CLASSES = {
    'file', 'dir', 'socket', 'lnk_file', 'chr_file', 'blk_file', 'fifo_file', 
    'service', 'property_service', 'service_manager', 'capability'
}

script_dir = os.path.dirname(os.path.abspath(__file__))
sepolicy_rule = os.path.join(script_dir, 'sepolicy.rule')
sepolicy_cil = os.path.join(script_dir, 'sepolicy.cil')
rules = 0
skipped = 0
filtered = 0

print("========SELinux audit allow========")

file = ""
while not file:
    input_file = input("- 请输入目标日志文件: ")
    if input_file == "exit":
        exit()
    if os.path.isfile(os.path.join(script_dir, input_file)):
        file = os.path.join(script_dir, input_file)
    elif os.path.isfile(input_file):
        file = input_file
    else:
        print(f"! 未找到日志文件: {input_file}\n")

print(f"\n- 目标日志文件: {file}")
print(f"- 目标输出文件: {sepolicy_rule}, {sepolicy_cil}")

def handle_target_file(target):
    if os.path.isfile(target) and os.path.getsize(target) > 0:
        action = input(f"\n! 目标输出文件 {target} 已存在\n- 您希望如何处理此文件?\n"
                      f"- 输入 y 或 yes 将续写此文件并跳过重复条目\n"
                      f"- 输入 n 或 no 将清空此文件并重新生成: ")
        if action.lower() in ["y", "yes"]:
            print(f"- 将续写 {target} 并跳过重复条目")
            with open(target, 'r', encoding='utf-8') as f:
                content = re.sub(r"[{}()]", "", f.read()).replace('allow ', '').strip()
            return set(line.strip() for line in content.splitlines() if line.strip())
        elif action.lower() in ["n", "no"]:
            print(f"- 清空 {target}")
            open(target, 'w').close()
            return set()
    else:
        open(target, 'w').close()
        return set()

start_time = time.time()

existing_rules = set()
for target in [sepolicy_rule, sepolicy_cil]:
    existing_rules.update(handle_target_file(target))

with open(file, 'r', encoding='utf-8') as f:
    log = [line for line in f if "avc:  denied" in line]

if not log:
    print("! 读取日志文件失败")
    exit(1)

rules_text_rule = ""
rules_text_cil = ""
rules_dict = {}

for error in log:
    scontext = extract_field(error, "scontext")
    tcontext_raw = extract_field(error, "tcontext")
    tclass = extract_field(error, "tclass")
    perms_match = re.search(r"{([^}]+)}", error)
    perms = perms_match.group(1).strip() if perms_match else ""

    tcontext = "self" if tcontext_raw == scontext else tcontext_raw

    if not scontext or not tcontext or not tclass or not perms:
        continue

    if ('magisk' in scontext.lower() or 'magisk' in tcontext.lower() or
        scontext in MAGISK_CONTEXTS or tcontext in MAGISK_CONTEXTS):
        filtered += 1
        continue

    if tclass not in VALID_CLASSES:
        filtered += 1
        continue

    rule_key = f"{scontext} {tcontext} {tclass} {perms}"
    if rule_key in existing_rules:
        skipped += 1
        continue

    all_config = f"{scontext} {tcontext} {tclass}"
    if all_config in rules_dict:
        existing_perms = rules_dict[all_config]
        rules_dict[all_config] = merge_permissions(existing_perms, perms)
    else:
        rules_dict[all_config] = perms

for all_config, perms in rules_dict.items():
    scontext, tcontext, tclass = all_config.split(' ', 2)
    rule_line = f"{scontext} {tcontext} {tclass} {perms}"
    if rule_line not in existing_rules:
        rules_text_rule += f"allow {scontext} {tcontext}:{tclass} {{ {perms} }}\n"
        perms_split = ' '.join(f"({p})" for p in perms.split())
        rules_text_cil += f"(allow {scontext} {tcontext} ({tclass} ({perms_split})))\n"
        rules += 1
        existing_rules.add(rule_line)

with open(sepolicy_rule, 'a', encoding='utf-8') as f:
    f.write(rules_text_rule)

with open(sepolicy_cil, 'a', encoding='utf-8') as f:
    f.write(rules_text_cil)

remove_empty_lines(sepolicy_rule)
remove_empty_lines(sepolicy_cil)

end_time = time.time()
elapsed_time = end_time - start_time

print(f"- 规则生成完成，共生成 {rules} 条新规则，跳过 {skipped} 条重复规则，过滤 {filtered} 条无效规则，耗时 {elapsed_time:.2f} 秒")
exit(0)

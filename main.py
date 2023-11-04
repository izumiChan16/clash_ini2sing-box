import pandas as pd
import concurrent.futures
import json


def read_file(file_name):
    with open(file_name, 'r', encoding='utf8') as f:
        ini_file = f.read()

    # 提取规则
    rules = []
    for line in ini_file.splitlines():
        if line.startswith('ruleset='):
            rules.append(line.split('=')[1])

    # 提取规则组
    groups = []
    for line in ini_file.splitlines():
        if line.startswith('custom_proxy_group='):
            groups.append(line.split('=')[1])

    return rules, groups


def parse_rules(rules):
    # 提取outbound名称和list链接
    outbound_name = []
    list_link = []

    # 提取含有[]的rules
    no_group_rules = []
    for rule in rules:
        if '[]' in rule:
            no_group_rules.append(rule)

    # 删除含有[]的rules
    for rule in no_group_rules:
        rules.remove(rule)

    for rule in rules:
        # 🎯 全球直连,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list
        outbound_name.append(rule.split(',')[0])
        list_link.append(rule.split(',')[1])

    # 生成字典
    rules_dict = {}
    # 处理重复的outbound
    for i, key in enumerate(outbound_name):
        if key not in rules_dict:
            rules_dict[key] = [list_link[i]]
        else:
            rules_dict[key].append(list_link[i])

    rules_list = []
    # 生成列表, "outbound"的值为key，""rule"的值为相应的links
    for key, value in rules_dict.items():
        rules_list.append({'outbound': key, 'rule': value})

    return rules_list, no_group_rules


def read_csv_and_append(link):
    return pd.read_csv(link, header=None, names=['pattern', 'address'], on_bad_lines='warn')


def parse_list_file(list_links):
    # 读取全部链接，拼接为一个df， 读取list链接，设置header为pattern和address
    # 使用多线程池来并行处理链接
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(read_csv_and_append, list_links))
        df = pd.concat(results, ignore_index=True)

    # 删除pattern中包含#号的行
    df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)

    # 映射字典
    # DOMAIN-SUFFIX、DOMAIN、DOMAIN-KEYWORD、IP-CIDR、SRC-IP-CIDR、GEOIP、DST-PORT、SRC-PORT
    map_dict = {'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'DOMAIN-KEYWORD': 'domain_keyword',
                'IP-CIDR': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
                'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex"}

    # 删除不在字典中的pattern
    df = df[df['pattern'].isin(map_dict.keys())].reset_index(drop=True)
    # 替换pattern为字典中的值
    df['pattern'] = df['pattern'].replace(map_dict)

    # 使用 groupby 分组并转化为字典
    result_dict = df.groupby('pattern')['address'].apply(list).to_dict()

    return result_dict


def generate_rules(rules_list, no_group_rules):
    # 遍历rules_list
    # 将rule传入parse_list_file函数，返回字典
    rules_dict_list = []

    for rule in rules_list:
        # 传入list链接的列表，返回字典
        rule_dict = parse_list_file(rule['rule'])
        rule_dict['outbound'] = rule['outbound']
        rules_dict_list.append(rule_dict)

    no_group_rules_dict_list = []
    final_value = ''
    for rule in no_group_rules:
        # 如果包含[]GEOIP，改为geoip
        if '[]GEOIP' in rule:
            rule = rule.replace('[]GEOIP', 'geoip')
            rule_dict = {'outbound': rule.split(',')[0], 'geoip': rule.split(',')[2].lower()}
            no_group_rules_dict_list.append(rule_dict)
        if '[]FINAL' in rule:
            final_value = rule.split(',')[0]

    return rules_dict_list, no_group_rules_dict_list, final_value


def parse_groups(groups):
    # 提取组名称和组内容
    # 🚀 节点选择`select`[]♻️ 自动选择`[]🚀 手动切换`[]🔎 IPLC`[]🇭🇰 香港节点`[]🇨🇳 台湾节点`[]🇸🇬 狮城节点`[]🇯🇵 日本节点`[]🇺🇲 美国节点`[]🇬🇧 英国节点`[]🇰🇷 韩国节点`[]DIRECT
    group_name = []
    type_name = []
    outbounds_name = []

    # 重新按逗号分割修改groups的值
    for i, group in enumerate(groups):
        groups[i] = group.split(',')[0]

    # 提取组名称
    for group in groups:
        group_name.append(group.split('`')[0])
        type_name.append(group.split('`')[1])
        outbounds_name.append(group.split('`')[2:])
    # 生成列表
    groups_dict = []
    for i, key in enumerate(group_name):
        if type_name[i] == 'select':
            type_name[i] = 'selector'
        elif type_name[i] == 'url-test':
            type_name[i] = 'urltest'
            # 并且将outbounds删除倒数两个值
            outbounds_name[i] = outbounds_name[i][:-2]
        elif type_name[i] == 'fallback':
            type_name[i] = 'urltest'
        groups_dict.append({'tag': key, 'type': type_name[i], 'outbounds': outbounds_name[i]})

    # 遍历outbounds，包含[]的是组，不包含[]的是正则表达式
    # 包含正则表达式的字典新加一个key:value，key为filter，value为字典，字典中包含key为"action", "keywords"，action的值为"conclude"，keywords的值为正则表达式
    # 不包含正则表达式的字典不做改动
    for group in groups_dict:
        # 遍历type，select改为selector，url-test改为urltest，fallback改为urltest
        for i, type_n in enumerate(group['type']):
            if type_n == 'select':
                group['type'][i] = 'selector'
            elif type_n == 'url-test':
                group['type'][i] = 'urltest'
                # 并且将outbounds删除倒数两个值
                group['outbounds'] = group['outbounds'][:-2]
            elif type_n == 'fallback':
                group['type'][i] = 'urltest'

        for i, outbound in enumerate(group['outbounds']):
            if '[]' in outbound:
                # 如果包含DIRECT,改为direct,如果包含REJECT,改为block
                if 'DIRECT' in outbound:
                    group['outbounds'][i] = 'direct'
                    continue
                elif 'REJECT' in outbound:
                    group['outbounds'][i] = 'block'
                    continue
                group['outbounds'][i] = outbound.split('[]')[1]
            else:
                group['outbounds'][i] = "{all}"
                group['filter'] = [{'action': 'include', 'keywords': [outbound]}]

    return groups_dict


def load_to_template():
    pass


def main():
    rules, groups = read_file('SelfSimple.ini')
    rules_list, no_group_rules = parse_rules(rules)
    rules_dict_list, no_group_rules_dict_list, final_value = generate_rules(rules_list, no_group_rules)
    groups_dict = parse_groups(groups)

    # 加载模板
    with open('template.json', 'r', encoding='utf8') as f:
        template = json.load(f)

    # 在template["outbounds"]前面插入groups_dict
    template["outbounds"] = groups_dict + template["outbounds"]
    template["route"]["rules"] = template["route"]["rules"] + rules_dict_list + no_group_rules_dict_list
    template["route"]["final"] = final_value

    with open('config.json', 'w', encoding='utf8') as f:
        json.dump(template, f, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    main()

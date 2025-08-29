import os
import re
import shlex
import datetime
import requests
import ipaddress

def load_source(url):
    paths = [url, os.path.join(os.path.dirname(os.path.abspath(__file__)), url)]
    if url.startswith("https://"):
        try: r = requests.get(url); r.raise_for_status(); return r.text
        except Exception: print(f"Failed to download {url}"); return None
    for p in paths:
        if os.path.isfile(p):
            try: return open(p, encoding='utf-8').read()
            except Exception: print(f"Failed to read {p}"); return None
    print(f"Local file not found: {paths[-1]}"); return None

def build_sgmodule(rule_text, project_name):
    formatted_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
    header_lines = [f"#!name={project_name}", f"#!desc={formatted_time}"]
    arguments_list = re.findall(r'^\s*#!arguments\s*=\s*(.+)', rule_text, re.MULTILINE)
    arguments_list = [", ".join(part.strip() for part in line.split(',')) for line in arguments_list]
    if arguments_list:
        header_lines.append("#!arguments=" + ", ".join(arguments_list))
    desc_matches = re.findall(r'^\s*#!arguments-desc\s*=\s*(.+)', rule_text, re.MULTILINE)
    desc_items = [desc.strip() for line in desc_matches for desc in line.split('；') if desc.strip()]
    if desc_items:
        header_lines.append(f"#!arguments-desc=\\n 参数说明：\\n {'；\\n '.join(desc_items)}；\\n ")
    sgmodule_content = '\n'.join(header_lines) + '\n' if header_lines else ''

    rule_pattern = r'^(?!#)(.*?)\s*(DOMAIN(?:-SUFFIX|-KEYWORD)?|IP-CIDR|AND|URL-REGEX),'
    priority_list = ['DOMAIN,', 'DOMAIN-SUFFIX,', 'DOMAIN-KEYWORD,', 'IP-CIDR,', 'AND,', 'URL-REGEX,']
    priority_index = {p: i for i, p in enumerate(priority_list)}
    rule_lines = []
    for line in rule_text.splitlines():
        line = line.strip()
        if line and re.match(rule_pattern, line):
            rule_lines.append(line)
    rule_lines = list(set(rule_lines))
    rule_lines.sort(key=lambda x: (
        priority_index.get(next((p for p in priority_list if x.startswith(p)), ''), len(priority_list)),
        (lambda ip: 0 if ip and ip.version == 4 else 1 if ip and ip.version == 6 else 2)(
            (lambda s: ipaddress.ip_address(s) if s and re.match(r'^\d', s) else None)(
                x.split(',')[1].split('/')[0].strip() if x.startswith('IP-CIDR,') and ',' in x and '/' in x else ''
            )
        ),
        (lambda s: list(ipaddress.ip_address(s).packed) if s and re.match(r'^\d', s) else [999] * 16)(
            x.split(',')[1].split('/')[0].strip() if x.startswith('IP-CIDR,') and ',' in x and '/' in x else ''
        ),
        x.upper()
    ))
    sgmodule_content += "\n[Rule]\n" + '\n'.join(rule_lines) + '\n' if rule_lines else ''

    rewrite_pattern = r'^(?!#)(.*?)\s*url\s+(reject(?:-200|-array|-dict|-img|-tinygif)?)'
    redirect_pattern = r'^(?!#)(.*?)\s*url\s+(302|307|header)\s+(.*)$'
    url_rewrite_lines = []
    for match in re.finditer(rewrite_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        reject_type = match.group(2).strip()
        url_rewrite_lines.append(f"{pattern} - {reject_type}")
    for match in re.finditer(redirect_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        destination = match.group(3).strip()
        redirect_type = match.group(2).strip()
        url_rewrite_lines.append(f"{pattern} {destination} {redirect_type}")
    sgmodule_content += "\n[URL Rewrite]\n" + '\n'.join(sorted(set(url_rewrite_lines))) + '\n' if url_rewrite_lines else ''

    maplocal_pattern = r'^(?!#)(.*?)\s*mock-response-body\s+(.*)$'
    map_local_lines = []
    for match in re.finditer(maplocal_pattern, rule_text, re.MULTILINE):
        regex, params_str = match.group(1).strip(), match.group(2).strip()
        data_match = re.search(r'data=\s*(["\'].*["\']|{.*}|\[.*\])', params_str)
        data = data_match.group(1) if data_match else ''
        params_str_wo_data = params_str[:data_match.start()] + params_str[data_match.end():] if data_match else params_str
        lexer = shlex.shlex(params_str_wo_data, posix=False)
        lexer.whitespace_split = True
        lexer.commenters = ''
        lexer.quotes = '"'
        lexer.wordchars += ':/-._?&'
        kv_pairs = dict(token.split('=', 1) for token in lexer if '=' in token)
        data_type = kv_pairs.get('data-type', '').lower()
        status_code = kv_pairs.get('status-code', '')
        is_base64 = kv_pairs.get('mock-data-is-base64', '').lower() == 'true'
        status_code = status_code or ('200' if data_type == 'json' else status_code)
        data = data[1:-1] if data.startswith('"') and data.endswith('"') else data
        if is_base64 or data_type == 'base64': content_type = 'application/octet-stream'
        elif data_type in ('json','text') and (data.strip().startswith('{') or data.strip().startswith('[')): content_type = 'application/json'
        elif data_type in ('json','text'): content_type = 'text/plain'
        else: content_type = 'application/octet-stream'
        line = f'{regex} data-type={data_type} data="{data}"'
        line += f' status-code={status_code}' if status_code else ''
        line += f' header="content-type: {content_type}"' if 'header' not in kv_pairs else ''
        map_local_lines.append(line)
    sgmodule_content += "\n[Map Local]\n" + '\n'.join(sorted(set(map_local_lines))) + '\n' if map_local_lines else ''

    body_pattern = r'^(?!#)(.*?)\s*url\s+jsonjq-response-body\s+(.*)$'
    body_jq_lines = []
    for match in re.finditer(body_pattern, rule_text, re.MULTILINE):
        body_matcher = match.group(1).strip()
        body_expr = match.group(2).strip()
        if body_expr.startswith("'") and body_expr.endswith("'"):
            line = f"http-response-jq {body_matcher} {body_expr}"
            body_jq_lines.append(line)
        elif body_expr.startswith('jq-path="') and body_expr.endswith('"'):
            line = f"http-response-jq {body_matcher} {body_expr}"
            body_jq_lines.append(line)
    sgmodule_content += "\n[Body Rewrite]\n" + '\n'.join(sorted(set(body_jq_lines))) + '\n' if body_jq_lines else ''

    script_pattern = r'^(?!#)(.*?)\s*url\s+(script-(?:response|request)-(?:body|header)|script-echo-response|script-analyze-echo-response)\s+(\S+)'
    script_lines = []
    for match in re.finditer(script_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        script_type_raw = match.group(2)
        script_path = match.group(3).strip().rstrip(',')
        filename_match = re.search(r'/([^/]+?)(?:\.js)?$', script_path)
        filename = filename_match.group(1).strip() if filename_match else script_path
        script_type = 'response' if script_type_raw in ['script-response-body', 'script-echo-response', 'script-response-header'] else 'request'
        needbody = "true" if script_type_raw in ['script-response-body', 'script-echo-response', 'script-response-header', 'script-request-body', 'script-analyze-echo-response'] else "false"
        params = [f"{filename} =type=http-{script_type}", f"pattern={pattern}", f"script-path={script_path}", f"requires-body={needbody}", "max-size=0"]
        line_start = match.start()
        line_end = rule_text.find('\n', line_start)
        line = rule_text[line_start:line_end if line_end != -1 else None]
        binary_body_mode_match = re.search(r'binary-body-mode\s*=\s*(true|false)', line)
        if binary_body_mode_match:
            params.append(f"binary-body-mode={binary_body_mode_match.group(1)}")
        argument_match = re.search(r'argument\s*=\s*(["\'].*["\']|{.*}|\[.*\])', line)
        if argument_match:
            params.append(f'argument={argument_match.group(1)}')
        script_line = ', '.join(params)
        script_lines.append(script_line)
    replace_pattern = r'^(?!#)(.*?)\s*url\s+(response-body)\s+(\S+)\s+(response-body)\s+(\S+)'
    replace_lines = []
    for match in re.finditer(replace_pattern, rule_text, re.MULTILINE):
        pattern = match.group(1).strip()
        re1 = match.group(3).strip()
        re2 = match.group(5).strip()
        line = f"ReplaceBody =type=http-response, pattern={pattern}, script-path=https://xiangwanguan.github.io/Shadowrocket/Rewrite/JavaScript/ReplaceBody.js, requires-body=true, max-size=0, argument={re1}->{re2}"
        replace_lines.append(line)
    combined_script_lines = script_lines + replace_lines
    sgmodule_content += "\n[Script]\n" + '\n'.join(sorted(set(combined_script_lines))) + '\n' if combined_script_lines else ''

    mitm_pattern = r'^\s*hostname\s*=\s*([^\n#]*)\s*(?=#|$)'
    mitm_matches = set()
    for match in re.finditer(mitm_pattern, rule_text, re.MULTILINE):
        hostnames = match.group(1).split(',')
        mitm_matches.update(host.strip().lower() for host in hostnames if host.strip())
    mitm_match_content = ','.join(sorted(mitm_matches, key=lambda host: (0 if host.startswith('-') else 1, host)))
    sgmodule_content += "\n[MITM]\n" + f"hostname = %APPEND% {mitm_match_content}\n" if mitm_match_content else ''

    return sgmodule_content

def save_sgmodule(content, path):
    try: open(path, 'w', encoding='utf-8').write(content)
    except Exception as e: print(f"Failed to save output file: {path}: {e}")

def generate_app_modules(rules, parent_dir):
    dir_modules = os.path.join(parent_dir, "Release", "Modules")
    os.makedirs(dir_modules, exist_ok=True)
    for f in os.listdir(dir_modules):
        fp = os.path.join(dir_modules, f)
        if os.path.isfile(fp): os.remove(fp)
    apps, buf, current = {}, [], None
    for line in rules.splitlines():
        if line.startswith("# >"):
            if current and buf: apps[current] = "\n".join(buf); buf=[]
            current=line[3:].strip()
        elif current: buf.append(line)
    if current and buf: apps[current] = "\n".join(buf)
    for app, text in apps.items():
        content = "\n".join(l for l in build_sgmodule(text, app).splitlines() if not l.startswith('#!desc=')) + "\n"
        save_sgmodule(content, os.path.join(dir_modules, f"{app}.sgmodule"))

def generate_main_sgmodule(sources, parent_dir):
    merged = "\n".join(filter(None, (load_source(u) for u in sources)))
    if not merged: return print("No valid rules found — module generation skipped.")
    content = build_sgmodule(merged, "融合模块")
    if content: save_sgmodule(content, os.path.join(parent_dir, "Release", "Module.sgmodule")); print(content)
    generate_app_modules(merged, parent_dir)

def main():
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try: entries=[l.strip() for l in open(os.path.join(parent_dir,"Generator","Generate.conf")) if l.strip() and not l.startswith('#')]
    except Exception as e: return print(f"Failed to read input file: {e}")
    generate_main_sgmodule(entries, parent_dir)

if __name__=="__main__": main()

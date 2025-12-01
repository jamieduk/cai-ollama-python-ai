#!/usr/bin/env python3
# CAI Blue/Red Team Pentest Framework (c) J~Net 2025

import os,sys,json,shlex,subprocess,socket,requests,importlib,glob,difflib

CONFIG_FILE="config.json"
MODULE_DIR="modules"
LAST_CMD_FILE="last.txt"
LOG_FILE="scan.log"

DEFAULT_CONFIG={
    "provider_url":"http://127.0.0.1:11434",
    "default_model":"deepseek-v3.1:671b-cloud",
    "full_auto_next_step":0,
    "nmap_args":"-sS -Pn -T4",
    "vuln_script":True,
    "scan_timeout":300,
    "mode":1
}

def ensure_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE,'w') as f:
            json.dump(DEFAULT_CONFIG,f,indent=4)
        print("Created default config.json")

# (c) J~Net 2025
def load_config():
    with open(CONFIG_FILE,"r") as f:
        data=json.load(f)
    for k,v in DEFAULT_CONFIG.items():
        if k not in data:
            data[k]=v
    with open(CONFIG_FILE,"w") as f:
        json.dump(data,f,indent=4)
    return data

def save_last(cmd):
    with open(LAST_CMD_FILE,"w") as f:
        f.write(cmd)

def load_last():
    if not os.path.exists(LAST_CMD_FILE):
        return ""
    return open(LAST_CMD_FILE).read().strip()

# (c) J~Net 2025
def ask_model(prompt):
    try:
        model=cfg.get("default_model",DEFAULT_CONFIG["default_model"])
        url=cfg.get("provider_url",DEFAULT_CONFIG["provider_url"])
        payload={"model":model,"prompt":prompt,"stream":False}
        r=requests.post(f"{url}/api/generate",json=payload,timeout=60)
        if r.status_code!=200:
            return "LLM error: "+r.text
        j=r.json()
        return j.get("response","").strip()
    except Exception as e:
        return "Ollama request failed: "+str(e)

def ensure_modules_folder():
    if not os.path.exists(MODULE_DIR):
        os.mkdir(MODULE_DIR)
        with open(os.path.join(MODULE_DIR,"example_module.py"),"w") as f:
            f.write("TAGS=['example']\n\ndef ability():\n    return 'example ability loaded'\n")

# (c) J~Net 2025
def ollama_generate(prompt,model,url,timeout=60):
    payload={"model":model,"prompt":prompt,"stream":False}
    try:
        r=requests.post(f"{url}/api/generate",json=payload,timeout=timeout)
        if r.status_code!=200:return "LLM error: "+r.text
        j=r.json()
        return j.get("response","").strip()
    except Exception as e:
        return "Ollama request failed: "+str(e)

def detect_router_ip():
    try:
        with open('/proc/net/route') as f:
            for line in f.readlines()[1:]:
                p=line.split()
                if p[1]=="00000000":
                    gw=int(p[2],16)
                    return ".".join(str((gw>>8*i)&255) for i in range(4))
    except:pass
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        s.connect(('8.8.8.8',80))
        ip=s.getsockname()[0]
        s.close()
        parts=ip.split('.')
        parts[-1]="1"
        return ".".join(parts)
    except:
        return None

def set_active_target(text,config):
    import re,json
    ips=re.findall(r"(?:\d{1,3}\.){3}\d{1,3}",text)
    if ips:
        config["active_target"]=ips[0]
        with open("config.json","w") as f:
            f.write(json.dumps(config,indent=2))
        return ips[0]
    if "active_target" in config and config["active_target"]:
        return config["active_target"]
    return None

# (c) J~Net 2025
def run_latest_module():
    files=sorted(os.listdir(MODULE_DIR))
    mods=[f for f in files if f.startswith("mod_") and f.endswith(".py")]
    if not mods:
        print("[no modules found]")
        return
    latest=mods[-1]
    name=latest[:-3]
    try:
        mod=importlib.import_module(f"modules.{name}")
        importlib.reload(mod)
        print(f"[executing newest module {name}]")
        mod.ability()
    except Exception as e:
        print("[module execution failed]",e)


# (c) J~Net 2025
def run_nmap(target):
    args=shlex.split(f"nmap {cfg['nmap_args']} {target}")
    if cfg["vuln_script"]:
        args+=["--script","vuln"]
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=cfg["scan_timeout"])
        out=(p.stdout or b"").decode("utf-8",errors="ignore")
        log=f"\n---CMD---\n{' '.join(args)}\n---OUTPUT---\n{out}\n---END---\n"
        open(LOG_FILE,"a").write(log)
        return out
    except Exception as e:
        return f"nmap failed: {e}"

def parse_open_ports(out):
    ports=[]
    for line in out.splitlines():
        if "/tcp" in line or "/udp" in line:
            s=line.split()
            if len(s)>=2 and s[1].lower()=="open":
                ports.append(s[0])
    return ports

# (c) J~Net 2025
def analyse_and_next_step(nmap_output):
    safe_output=str(nmap_output) if nmap_output is not None else ""
    prompt=("You are a cyber‑security analyst. Based on the NMAP output below, provide a prioritised pentest plan and next recommended steps.\n\n"+safe_output)
    try:
        ai=ask_model(prompt)
    except Exception as e:
        ai="AI analysis failed: "+str(e)
    print("\n--- AI Security Analysis ---")
    print(ai)
    print("--- End ---\n")
    try:
        next_cmd=ask_model("Based on the scan analysis, output ONLY the next shell command to run. No explanation. Use 'none' if nothing should be executed.")
    except Exception as e:
        next_cmd="none"
    next_cmd=str(next_cmd).strip() if next_cmd else "none"
    if next_cmd.lower()=="none" or next_cmd=="":
        print("[No next step required]")
        return
    active_target=set_active_target("",cfg) or "127.0.0.1"
    next_cmd=sanitize_next_step(next_cmd,active_target)
    print(f"\nAI recommends next step: {next_cmd}")
    if int(cfg.get("full_auto_next_step",0))==1:
        print("[Auto‑executing]")
        run_and_log(next_cmd)
        return
    yn=input("Run this step? (y/N): ").strip().lower()
    if yn=="y":
        run_and_log(next_cmd)
    else:
        print("Skipped.")

def run_and_log(cmd):
    try:
        p=subprocess.run(shlex.split(cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out=p.stdout.decode("utf-8","ignore")
        open(LOG_FILE,"a").write(f"\n---RUN---\n{cmd}\n{out}\n")
        print(out)
    except Exception as e:
        print("Execution failed:",e)

def sanitize_next_step(cmd,active_target):
    import re
    cmd=re.sub(r"(?:\d{1,3}\.){3}\d{1,3}",active_target,cmd)
    if active_target not in cmd:
        cmd=f"{cmd} {active_target}"
    return cmd

def handle_scan_router():
    router=detect_router_ip()
    if not router:
        print("Unable to detect router IP")
        return
    handle_scan_target(router)

def handle_scan_target(target):
    print(f"Scanning {target}...")
    out=run_nmap(target)
    print("\n--- nmap output start ---")
    print(out)
    print("--- nmap output end ---\n")
    ports=parse_open_ports(out)
    if ports:
        print(f"Open ports: {ports}")
    analyse_and_next_step(out)

# MODULE SYSTEM ---------------------------------------------------

def load_modules():
    mods={}
    for p in glob.glob(f"{MODULE_DIR}/*.py"):
        name=os.path.splitext(os.path.basename(p))[0]
        try:
            spec=importlib.util.spec_from_file_location(name,p)
            mod=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not hasattr(mod,"TAGS"):
                mod.TAGS=[]
            mods[name]=mod
        except Exception as e:
            print(f"[Module Load Error] {name}: {e}")
    return mods

# (c) J~Net 2025
def try_module(cmd):
    low=cmd.lower()
    for name,mod in modules.items():
        tags=[t.lower() for t in getattr(mod,"TAGS",[])]
        for t in tags:
            if t in low or low in t:
                try:
                    print(f"[executing module {name}]")
                    mod.ability()
                    return True
                except Exception as e:
                    print(f"[Module Error {name}]: {e}")
                    return True
    return False


# **** NEW: directly run ability after extension ****
# (c) J~Net 2025
def run_generated_ability(cmd):
    ok=try_module(cmd)
    return ok


# AUTO‑EXTEND ------------------------------------------------------

#------------------------------------------------------------
# AUTO‑EXTEND WITH REAL EXECUTABLE ABILITIES (c) J~Net 2025
#------------------------------------------------------------
# (c) J~Net 2025
def extend(cmd):
    prompt=(
        "Write a Python module implementing the command:\n"
        f"{cmd}\n\n"
        "Rules:\n"
        "- Provide TAGS=list of natural language tags.\n"
        "- Provide ability() that performs the action.\n"
        "- Real code only, import everything needed.\n"
        "- Print results directly.\n"
        "- No placeholders.\n"
        "- No shorthand.\n"
        "- Ability must extract all targets, URLs, text etc from the cmd string.\n"
    )

    raw=ask_model(prompt)
    code=raw.replace("```python","").replace("```","")

    if "def ability" not in code:
        code="TAGS=['generic']\ndef ability():\n    print('Auto‑extend failed')\n"

    h=abs(hash(cmd))%10**8
    fname=f"mod_{h}.py"
    path=os.path.join(MODULE_DIR,fname)

    with open(path,"w") as f:
        f.write(code)

    # run it immediately
    print(f"[auto-extended] module created: {path}")
    reload_modules()
    run_latest_module()




def reload_modules():
    global modules
    modules=load_modules()

# COMMAND DISPATCH ------------------------------------------------

# (c) J~Net 2025
def handle_command(cmd):
    if cmd=="":
        cmd=load_last()
        print(f"[using last command] {cmd}")
    save_last(cmd)
    low=cmd.lower()

    # special commands
    if low=="scan my router":
        handle_scan_router();return
    if low.startswith("scan "):
        target=cmd.split(" ",1)[1]
        handle_scan_target(target);return

    # 1) try to execute existing module
    if try_module(cmd):
        return

    # 2) auto extend if nothing matches
    print("[no matching ability → extending skillset]")
    extend(cmd)


# MAIN LOOP --------------------------------------------------------

def repl():
    while True:
        try:
            cmd=input("cai> ").strip()
            if cmd in ["exit","quit"]:
                break
            handle_command(cmd)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("Error:",e)

ensure_config()
cfg=load_config()
ensure_modules_folder()
modules=load_modules()

if __name__=="__main__":
    repl()

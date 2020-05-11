from sys import platform
import subprocess
import os

def read_config_file(config : str) -> list:
    try:
        with open(config, "r") as config_file:
            confs = config_file.readlines()
    except FileNotFoundError:
        print("""[Error] Could not find config file.""")
        exit(0)
    return [x.split(" : ")[1][:-1] for x in confs if not x == "\n"]

def write_report_card(where : str, fuzzer : str, nop_multiplier : int, wordlist : str) -> str:

        path = ""

        report_card = f"""
        \~~~~OverFuzz Report Card~~~~/
            Success = {success}\n
            Fuzzer = {fuzzer}\n
            Wordlist = {wordlist}\n
            Nop Mult. = {nop_multiplier}\n
            Where = {where}\n
        Made by luwzko.
        """
        with open(path + "OverFuzz_Report_Card.txt", "w+") as f:
            f.write(report_card)
        return path

def clear() -> None:
    try:
        if platform == "linux" or platform == "linux2" or platform == "darwin":
            os.system("clear")
        elif platform == "win32":
            os.system("cls")
    except KeyboardInterrupt:
        exit(0)

def exec_command(cmd : str, output : list, signal : list) -> None:

    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        status = 0
    except subprocess.CalledProcessError as ex:
        output = ex.output
        status = ex.returncode
    if output[-1:] == '\n':
        output = output[:-1]

    output.append(status)
    signal.append(output)

def banner():
    print("""
 ██████╗ ██╗   ██╗██████╗ ██████╗ ███████╗██╗   ██╗███████╗███████╗
██╔═████╗██║   ██║╚════██╗██╔══██╗██╔════╝██║   ██║╚══███╔╝╚══███╔╝
██║██╔██║██║   ██║ █████╔╝██████╔╝█████╗  ██║   ██║  ███╔╝   ███╔╝
████╔╝██║╚██╗ ██╔╝ ╚═══██╗██╔══██╗██╔══╝  ██║   ██║ ███╔╝   ███╔╝
╚██████╔╝ ╚████╔╝ ██████╔╝██║  ██║██║     ╚██████╔╝███████╗███████╗
 ╚═════╝   ╚═══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝""")

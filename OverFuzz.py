from sys import argv, setrecursionlimit
import threading
from utils.util import *
from fuzzers.overfuzz import *

def main() -> None:

    banner()

    confs = read_config_file(argv[1])

    overfuzz = OverFuzz(confs[3], confs[2], confs[4])

    overfuzz._overfuzz()

if __name__ == "__main__":
    setrecursionlimit(65535)
    try:
        main()
    except RecursionError:
        path = write_report_card("", "", 0, "")
        print(f"[!] Done, report card can be found @ {path}")

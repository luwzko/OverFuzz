from utils.util import *
import threading
import random

class OverFuzz():

    def __init__(self, file : str, detection_method : str, estimated_vars : int):

        self.__file = file
        self.__estimated_vars = estimated_vars
        self.__outputs = []
        self.__signals = []
        self.__detection = detection_method
        self.__multiplier = 1

        if self.__detection.lower() == "mixed":
            self.__detection = self.__mixed_detect
        elif self.__detection.lower() == "signal":
            self.__detection = self.__signal_detect
        elif self.__detection.lower() == "output":
            self.__detection = self.__output_detect

    def fuzz(self) -> None:

        print("(0ver) Fuzzing.")

        self.__multiplier += 1

        command0, command1 = self.__input_both()

        clear()
        banner()

        proc1 = threading.Thread(target=exec_command, args=(command0, self.__outputs, self.__signals))
        proc2 = threading.Thread(target=exec_command, args=(command1, self.__outputs, self.__signals))

        proc1.start()
        proc2.start()

        proc1.join()
        proc2.join()

        if self.__detection():
            path = write_report_card(True, "", "", 0, "")
            print(f"[!] Done, report card can be found @ {path}")
            exit(0)

        self._overfuzz()

    def __input_both(self) -> str:

        command0, command1 = self.__cmd_line()
        print_command = self.__stdin()

        command0 = command0.replace(".replace", print_command)
        command1 = command1.replace(".replace", print_command)

        return (command0, command1)

    def __stdin(self) -> str:

        nop = "\x90" * self.__multiplier
        return f'\'python -c \"print(u\'{"".join([f'{nop}{self.__gen_invalid_addr()}' for x in range(self.__estimated_vars)])}\')\"\''

    def __cmd_line(self) -> str:

        nop0 = (self.__multiplier * "\x90")
        nop1 = ((self.__multiplier + 1) * "\x90")

        addr0 = self.__gen_invalid_addr()
        addr1 = self.__gen_invalid_addr()

        pycmd_prince0 = f"\"print(\'{nop0}{addr0}\')\""
        pycmd_prince1 = f"\"print(\'{nop1}{addr1}\')\""

        pycmd_king0 = f"\'python -c {pycmd_prince0}\'"
        pycmd_king1 = f"\'python -c {pycmd_prince1}\'"

        if platform.startswith('win32') or platform.startswith('cygwin'):

            cmd_1 = f'FOR /F \"delims==\" %G IN ({pycmd_king0}) DO .replace {self.__file} %G'
            cmd_0 = f'FOR /F \"delims==\" %G IN ({pycmd_king1}) DO .replace {self.__file} %G'

        else:

            cmd_0 = f".replace | {self.__file} $({py_command_king_0})"
            cmd_1 = f".replace | {self.__file} $({py_command_king_1})"

        return (cmd_0, cmd_1)

    def __mixed_detect(self) -> bool:
        return self.__signal_detect() or self.__output_detect()

    def __signal_detect(self) -> bool:
        return any([ele for ele in [-11, 3221225725] if ele == self.__signals[-2] or ele == self.__signals[-1]])

    def __output_detect(self) -> bool:

        outs = ["segmentation", "buffer", "overflow", "seg", "smashing", "stack"]

        return any([ele for ele in out if ele.lower() in self.__outputs[-2].lower() or ele.lower() in self.__outputs[-1].lower()])

    def __gen_invalid_addr(self) -> str:

        rand1 = random.randint(16, 256)
        rand2 = random.randint(16, 256)
        rand3 = random.randint(16, 256)
        rand4 = random.randint(16, 256)

        return hex(rand1) + hex(rand2) + hex(rand3) + hex(rand4)

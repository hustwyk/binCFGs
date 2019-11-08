# binCFGs

**Aim :** Extract `ASM`, `C`, `IR` block CFG from binary file.

**Method :** `Angr` -> CFG, VexIR   ;   `objdump` -> Map(ASM, C)

**Store :** `yaml`

## Setup

**Environment** (Recommend version)

* python3(>=3.6)

* gcc(==6.5)

* objdump(==2.3)

**Requirement** (Recommend version)

* angr(==8.19.10.30)

* ruamel.yaml(==0.16.5)

* pyelftools(==0.25)

**Attention**

> When `pip3 install angr` finished, before run this python project, you have to modify one function of angr!

Locate `angr/block.py:294`

In `class CapstoneBlock -> def pp(self):`

Modify `print(str(self))` to `return str(self)`.

## Run

More information : `python3 extrfiles.py -h`

# ViDeZZo Bugs

This repo includes all bugs found by ViDeZZo and all bug reports.

## Convention

+ BUG_ID
  + target-idx, e.g., ati-00, ati-01, ati-02, the idx has two digits
+ BUG_ID.metadata
  + arch:                str: "i386|arm|aarch64|x86_64"
  + bug-types:          list: ["Assertion Failure"]
  + existing-bug-reports str: e.g., "https://xxx"
  + existing-patches     str: e.g., "https://xxx"
  + fixing-commit        str: e.g., "5288bee45fbd33203b61f8c76e41b15bb5913e6e"
  + hypervisor:          str: "qemu|vbox"
  + introducing-commit:  str: e.g., "5288bee45fbd33203b61f8c76e41b15bb5913e6e"
  + novelty:            bool: true|false
  + reproducible-commit: str: e.g., "5288bee45fbd33203b61f8c76e41b15bb5913e6e"
  + reproducible-host:   str: e.g., "Ubuntu 20.04"
  + reproducible-version:str: e.g., "7.0.50"
  + reward:              str: e.g., "CVE-XXXX-XXXX"
  + short-description:   str: e.g., "an assertion failure found in ati_2d()"
  + target:              str: e.g., "ati"
  + target-type:         str: audio|network|storage|usb|display
+ BUG_ID.backtrace:     text
+ BUG_ID.patch:         text
+ BUG_ID.reproduce:     text: command lines to reproduce
+ BUG_ID.description:     md: root cause and impact analysis

## Usage

1. Add a new bug by `python3 01-add-bug.py BUG_ID`.
2. Update BUG_ID.metadata manually in `./metadata/$BUG_ID/$BUG_ID.metadata`
3. Add the PoC to `./metadata/$BUG_ID`
4. Update BUG_ID.metadata manually in `./metadata/$BUG_ID/$BUG_ID.backtrace`
5. Evaluate security impacts of crashes, fix bugs and verify, submit patches and
discuss in communities. Apply for CVE and advertise if it is necessary. Update
`./metadata/$BUG_ID/$BUG_ID.patch`, `./metadata/$BUG_ID/$BUG_ID.reproduce`, and
`./metadata/$BUG_ID/$BUG_ID.description` manually.
6. Generate reports and a latex table by `python3 02-summarize-bug.py
all|bug-id`.

## Status

Predefined values
+ report-status: generated, reported
+ patch-status: None, preprared, revising, testing, merged

|bug-id|target|target-type|arch|bug-types|short-description|novelty|reward|report-status|patch-status|fixing-commit|
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
|ati-03|ati|display|i386|SEGV Write|hw/display/ati_2d: Third SEGV in ati_2d.c|True|None|generated|None|None|
|ac97-00|ac97|audio|i386|Abort|An abort was just triggered in audio_calloc|True|None|generated|None|None|
|smc91c111-00|smc91c111|net|arm|OOB read/wirte|OOB read/write in smc91c111|True|None|generated|None|None|



## Contribution

Please follow the above instructions and conventions to add a bug.

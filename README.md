# ViDeZZo Bugs

This repo includes all bugs found by ViDeZZo and all bug reports.

## Docker container for debugging

```
sudo docker build -t videzzo-bugs:latest .

# prepare the latest QEMU and VBox source code
# remember to checkout to a proper commit when debugging
git clone https://github.com/qemu/qemu.git
pushd qemu && patch -p 1 < ../0001-fix-assertion-in-hw-usb-core.c.patch && popd
svn co https://www.virtualbox.org/svn/vbox/trunk vbox

# prepare the crashing binary and poc
mkdir qemu-out-san # then copy related staff here
mkdir vbox-out-san # then copy related staff here

sudo bash -x run.sh # enter the docker

```

## Bug Database

1. Add a bug by `python3 01-add-bug.py BUG-ID`.
2. Update MATADATA manually

```
BUG-ID

+ target-idx, e.g., ati-00, ati-01, ati-02, the idx has two digits

MTATDATA-FILES

+ BUG-ID.metadata
  + short-description: str
  + hypervisor: str
  + arch: str
  + target: str
  + target-type: str
  + bug-types: list
  + novelty: str
  + existing-bug-reports if novelty is False: list
  + existing-patches if novelty is False: list
  + reproducible-version: str
  + reproducible-host: str
  + reproducible-commit: str
  + introducing-commit: str
  + fixing-commit if the bug is fixed: str
  + reward if any
+ BUG-ID.backtrace: text
+ BUG-ID.patch: text
+ BUG-ID.reproducer: text
+ BUG-ID.description: markdown
```

3. Generate reports and a latex table by `python3 02-summarize-bug.py all|bug-id`.

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

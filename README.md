# ViDeZZo Bugs

This repo includes all bugs found by ViDeZZo and all bug reports.

Due to more and more bugs, I am currently refactoring the whole repo
to scale to hundreds of bugs.

## Usage

1. Add a bug by `python3 01-add-bug.py BUG-ID`.
2. Update MATADATA manually
3. Generate reports and a latex table by `python3 02-summarize-bug.py all|bug-id`.

## Convention

### 1 BUG-ID

target-idx, e.g., ati-00, ati-01, ati-02, the idx has two digits

### 3 MTATDATA-FILES

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

## Status

Predefined values
+ report-status: generated, reported
+ patch-status: None, preprared, revising, testing, merged

|bug-id|target|target-type|arch|bug-types|short-description|novelty|reward|report-status|patch-status|fixing-commit|
|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|:|-|-|-|:|
|ati-03|ati-03|ati|display|i386|SEGV Write|hw/display/ati_2d: Third SEGV in ati_2d.c|True|None|generated|None|None|

## Contribution

Please follow the above instructions and conventions to add a bug.

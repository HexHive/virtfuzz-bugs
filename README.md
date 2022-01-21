# ViDeZZo Bugs

This repo includes all bugs found by ViDeZZo and all bug reports.

Due to more and more bugs, I am currently refactoring the whole repo
to scale to hundreds of bugs.

## Usage

1. Add a bug by `python3 add-bug.py BUG-ID`.
2. Update MATADATA manually
3. Generate reports and a latex table by `python3 summarize.py`.

## Convention

### 1 BUG-ID

target-idx, e.g., ati-00, ati-01, ati-02, the idx has two digits

### 3 MTATDATA-FILES

+ BUG-ID.metadata
  + hypervisor
  + arch
  + target
  + bug-types
  + novelty
  + existing-bug-reports if novelty is False
  + existing-patches if novelty is False
  + introduce-commit
  + patch-status
  + fix-commit if patch-status is merged
  + bug-report-status
+ BUG-ID.backtrace
+ BUG-ID.patch
+ BUG-ID.reproducer
+ BUG-ID.description

## Contribution

Please follow the above instructions and conventions to add a bug.

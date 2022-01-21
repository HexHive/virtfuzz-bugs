#!/usr/bin/python3
import os
import sys
import yaml

METADIR='metadata'

bug_id = sys.argv[1]
if bug_id.find('-') == -1:
    print('[-] A bug id must follow this format: TARGET-IDX.')
    exit(1)

existing_bugs = os.listdir(METADIR)
if bug_id in existing_bugs:
    print('[-] This bug id {} exists. Please update the index.'.format(bug_id))
    exit(1)

print('[+] Creating {} ...'.format(bug_id))
bug_pathname = os.path.join(METADIR, bug_id)
os.mkdir(bug_pathname)

# hypervisor: qemu, bhyve, virtualbox
# arch: i386, arm, aarch64
# bug-types, novelty: True or False
# existing-bug-reports, exsiting-patches: link0\nlink1
# introduce-commit: link
# patches: pathname0\npathname1
# patch-status: prepared or sent or revising or merged
# fix-commit: link
# bug-report-status: prepared or sent

metadata = {
    'hypervisor': None,
    'arch': None,
    'target': bug_id.split('-')[0],
    'bug-types': None,
    'novelty': None,
    'existing-bug-reports': None,
    'existing-patches': None,
    'introduce-commit': None,
    'patch-status': None,
    'fix-commit': None,
    'bug-report-status': None,
}

yaml.safe_dump({bug_id: metadata}, open('{}/{}.metadata'.format(bug_pathname, bug_id), 'w'), default_flow_style=False)
os.system('touch {}/{}.backtrace'.format(bug_pathname, bug_id))
os.system('touch {}/{}.patch'.format(bug_pathname, bug_id))
os.system('touch {}/{}.reproducer'.format(bug_pathname, bug_id))
os.system('touch {}/{}.description'.format(bug_pathname, bug_id))
print('[+] Done. Please update metadata in {}'.format(bug_pathname))

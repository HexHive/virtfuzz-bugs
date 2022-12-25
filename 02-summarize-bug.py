#!/usr/bin/python3
import os
import yaml
import argparse

def generate_report(bug_pathname, metadata):
    report = []

    # some preparation
    bug_id = os.path.basename(bug_pathname)
    report_pathname = "bug-reports/{}.md".format(bug_id)

    ## title
    report.extend(['# {}\n\n'.format(metadata['short-description'])])

    ## description
    description = open("metadata/{0}/{0}.description".format(bug_id)).readlines()
    if len(description) != 0:
        description.append('\n')
        report.extend(description)

    ## technique details
    report.extend([
        "## More details\n\n",
        "### Hypervisor, hypervisor version, upstream commit/tag, host\n\n",
        '{}, {}, {}, {}\n\n'.format(
            metadata['hypervisor'],
            metadata['reproducible-version'],
            metadata['reproducible-commit'],
            metadata['reproducible-host']),
        "### VM architecture, device, device type\n\n",
        '{}, {}, {}\n\n'.format(metadata['arch'], metadata['target'], metadata['target-type']),
        '### Bug Type: {}\n\n'.format('; '.join(metadata['bug-types'])),
    ])

    if metadata["novelty"]:
        ### Stack traces, crash details
        backtraces = open("metadata/{0}/{0}.backtrace".format(bug_id)).readlines()
        if len(backtraces) != 0:
            report.extend(["### Stack traces, crash details\n\n"])
            report.append("```\n")
            report.extend(backtraces)
            report.append("```\n\n")
        ### Reproducer steps
        reproducer = open("metadata/{0}/{0}.reproducer".format(bug_id)).readlines()
        if len(reproducer) != 0:
            report.extend(["### Reproducer steps\n\n"])
            report.extend(reproducer)
            report.append("\n")
    else:
        ### Existing bug reports
        report.extend(['### Existing bug reports\n\n'])
        for i in metadata['existing-bug-reports']:
            report.append(i)
            report.append('\n')
        report.append('\n')

    if metadata['existing-patches'] != None:
        report.extend(['## Existing patches\n\n'])
        for i in metadata['existing-patches']:
            report.append(i)
            report.append('\n')
        report.append('\n')

    report.extend(["## Contact\n\n"])
    report.extend([
        "Let us know if I need to provide more information.\n",
    ])

    with open(report_pathname, "w") as f:
        f.write("".join(report))
    metadata['report-status'] = 'generated'
    print('[+] report: {}'.format(report_pathname))

latex_title = [
    'target', 'target-type',
    'hypervisor', 'reproducible-version', 'arch',
    'short-description',
    'novelty',
    'status',
    'messages'
]

markdown_title = [
    'bug-id',
    'target', 'target-type',
    'hypervisor', 'reproducible-version', 'arch',
    'short-description',
    'bug-types',
    'novelty',
    'status'
]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-m', '--markdown', action='store_true', default=False, help='print summary in markdown')
    parser.add_argument('-l', '--latex', action='store_true', default=False, help='print summary in latex')
    parser.add_argument('bug_id', help='target-idx; \'all\' for all', nargs='+')
    args = parser.parse_args()

    bug_pathname_list = []
    for bug_id in os.listdir('metadata'):
        pathname_to_bug = os.path.join('metadata', bug_id)
        if not os.path.isdir(pathname_to_bug):
            continue
        if 'all' in args.bug_id:
            bug_pathname_list.append(pathname_to_bug)
        elif bug_id in args.bug_id:
            bug_pathname_list.append(pathname_to_bug)
        else:
            continue

    if len(bug_pathname_list) == 0:
        print('[-] empty bug list, exit')
    elif len(bug_pathname_list) == 1:
        print('[+] process {}'.format(bug_pathname_list[0]))
    else:
        print('[+] process {}'.format(' '.join(bug_pathname_list)))

    metadata_list = {}
    for bug_pathname in bug_pathname_list:
        # step 1: load metadata
        bug_id = os.path.basename(bug_pathname)
        print('[+] processing {}'.format(bug_id))
        metadata_pathname = os.path.join(bug_pathname, '{}.metadata'.format(bug_id))
        metadata = yaml.safe_load(open(metadata_pathname))
        # step 2: generate report
        generate_report(bug_pathname, metadata[bug_id])
        metadata[bug_id]['bug-id'] = bug_id
        metadata_list.update(metadata)

    # step 3: generate summary
    if args.markdown:
        markdown = ['|id|{}|'.format('|'.join(markdown_title)), '|:---:|{}|'.format('|'.join([':---:'] * (len(markdown_title))))]
    if args.latex:
        latex = []
    sorted_metadata_list = dict(sorted(metadata_list.items()))
    i = 0
    for bug_id, metadata in sorted_metadata_list.items(): # maybe we need to sort
        i += 1
        row = [str(i)]
        if args.markdown:
            for column in markdown_title:
                if (column == 'messages' and column not in metadata) or \
                        (column == 'status' and column not in metadata):
                    metadata[column] = 'WIP'
                cell = metadata[column]
                if column == 'novelty' and (cell is False or cell == 'false'):
                    if 'reported-by' in metadata:
                        cell = ', '.join(metadata['reported-by'])
                    else:
                        cell = 'Anonymous'
                if 'status' in metadata:
                    cell = metadata['status']
                else:
                    call = 'WIP'
                if cell is None:
                    row.append('None')
                elif isinstance(cell, list):
                    row.append(', '.join(cell))
                elif isinstance(cell, bool):
                    row.append(str(cell))
                else:
                    row.append(cell)
            markdown.append('|{}|'.format('|'.join(row)))
        if args.latex:
            for column in latex_title:
                if ((column == 'messages' and column not in metadata) or \
                        (column == 'status' and column not in metadata)):
                    metadata[column] = 'WIP'
                cell = metadata[column]
                if column == 'novelty' and (cell is False or cell == 'false'):
                    if 'reported-by' in metadata:
                        cell = ', '.join(metadata['reported-by'])
                    else:
                        cell = 'Anonymous'
                if cell is None:
                    row.append('None')
                elif isinstance(cell, list):
                    row.append(', '.join(cell).replace('_', '\\_'))
                elif isinstance(cell, bool):
                    row.append(str(cell).replace('_', '\\_'))
                elif isinstance(cell, int):
                    row.append(str(cell))
                else:
                    row.append(cell.replace('_', '\\_'))
            latex.append('{} \\\\'.format(' & '.join(row)))
    if args.markdown:
        print('\n'.join(markdown))
    if args.latex:
        print('\n'.join(latex))

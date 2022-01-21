import yaml
from prettytable import PrettyTable
from reportgen import main
import sys

reports = main(sys.argv)

title_row = [
	'fuzz_target',
    'target_type',
    'arch',
    'type',
    'description',
    'novelty',
    # 'report',
    # 'status',
    # 'patch',
    # 'url'
]

table = PrettyTable()
table.field_names = ['id'] + title_row

reports = dict(sorted(reports.items()))
i = 1
for _, details in reports.items():
    row = [details[column] for column in title_row]
    # if 'id' in details:
    #     row.insert(0, details['id'])
    # else:
    #     row.insert(0, i)
    row.insert(0, i)
    table.add_row(row)
    i += 1

print(table.get_csv_string(delimiter='\t'))
# print(table.get_string(sortby="id"))
print('https://gitlab.com/qemu-project/qemu/-/')
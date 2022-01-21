fuzz_target=$1

touch bug-reports/metadata/$fuzz_target.backtrace
touch bug-reports/metadata/$fuzz_target.diff
touch bug-reports/metadata/$fuzz_target.reproducer
touch bug-reports/metadata/$fuzz_target.txt
import os
import sys
import yaml

def main(argv):
    reports = yaml.safe_load(open("reports.yaml"))

    common = reports.pop("common")
    metadata = reports.pop("metadata")

    for bug, details in reports.items():
        report = []
        pathname = "bug-reports/{}.md".format(bug)
        report.extend([
            "tag: arch: {}\n".format(details["arch"]),
            "tag: type: {}\n".format(details["type"]),
            "\n",
        ])
        description = open("bug-reports/metadata/{}.txt".format(bug)).readlines()
        report.extend(description)
        if len(description):
            reports[bug]['description'] = description[0].strip().strip('#')
        else:
            reports[bug]['description'] = None
        report.append("\n")
        report.extend([
            "## More technique details\n\n",
            "### QEMU version, upstream commit/tag\n",
            common["QEMU version, upstream commit/tag"],
            "\n\n",
            "### Host and Guest\n",
            common["Host and Guest"],
            "\n\n",
        ])
        if details["novelty"]:
            report.extend(["### Stack traces, crash details\n\n"])
            report.append("```\n")
            report.extend(
                open("bug-reports/metadata/{}.backtrace".format(bug)).readlines())
            report.append("```\n\n")
        report.extend(["### Reproducer steps\n\n"])
        report.extend(
            open("bug-reports/metadata/{}.reproducer".format(bug)).readlines())
        report.append("\n")
        if details["patch"] != "None":
            report.extend(["## Suggested fix\n\n"])
            report.append("```\n")
            report.extend(
                open("bug-reports/metadata/{}.diff".format(bug)).readlines())
            report.append("```\n\n")
        report.extend(["## Contact\n\n"])
        report.extend([
            "Let me know if I need to provide more information.\n",
        ])

        with open(pathname, "w") as f:
            f.write("".join(report))
    return reports

if __name__ == "__main__":
    main(sys.argv)


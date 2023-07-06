#!/usr/bin/env python3


import argparse
import csv
import json
import pathlib
from typing import Dict, Set, Tuple


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Command line arguments parser
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("-ld", "--logs-dir", type=str, required=True, help="Directory with routersploit logs")
    parser.add_argument("-hdf", "--hash-data-file", type=str, required=False, default="exp-hashes-data.json", help="RCE hash codes map file")
    return parser


def extract_exploit_status(stdout_file: pathlib.Path, exp_hashes: Dict[str, str]) -> Tuple[str, Dict[str, Set[str]]]:
    """
    Process an stdout file and extract status of exploits that were run
    """

    logs_of_interest_marker = b"AAAAAAAAAA"
    log_separator = b" -> "
    log_status_not_vulnerable = b"is not vulnerable"
    log_status_unverified = b"Could not be verified"
    log_status_vulnerable = b"is vulnerable"
    rce_prefix = b"GHRCE_"
    name_prefix = b"Target: "
    result = {"vulnerable": set(), "not-vulnerable": set(), "needs-verification": set(), "error": set()}
    target_ip = None
    target_port = None
    name = ""
    exploit_map = dict()
    with stdout_file.open('rb') as fh:
        for line_num, aline in enumerate(fh, start=1):
            if logs_of_interest_marker in aline:
                aline = aline.rstrip(b'\n')
                log_data = aline.split(log_separator)[1].split(b' ')
                target_ip = str(log_data[0].split(b':')[0], "utf-8")
                target_port = str(log_data[0].split(b':')[1], "utf-8")
                exploit_name = str(log_data[2], "utf-8")
                exploit_data = (exploit_name, target_ip, target_port)
                exploit_map[exploit_name] = exploit_data
                if aline.endswith(log_status_vulnerable):
                    result["vulnerable"].add(exploit_data)
                elif aline.endswith(log_status_not_vulnerable):
                    result["not-vulnerable"].add(exploit_data)
                elif aline.endswith(log_status_unverified):
                    result["needs-verification"].add(exploit_data)
                else:
                    result["error"].add(exploit_data)
            elif aline.startswith(rce_prefix):
                # Convert hash to str since hashes dictionary has strings as keys
                exp_hash = str(aline.strip(), 'utf-8')
                exploit_name = exp_hashes.get(exp_hash, None)
                exploit_data = exploit_map[exploit_name]
                if exploit_data is None:
                    print(f"Found GHRCE hash at line {line_num} of {stdout_file} but couldn't find exploit name. This is a bug!")
                else:
                    # Mark exploit as vulnerable and remove it from other status' sets if already present (silently
                    # ignore if not)
                    result["vulnerable"].add(exploit_data)
                    result["not-vulnerable"].discard(exploit_data)
                    result["needs-verification"].discard(exploit_data)
                    result["error"].discard(exploit_data)
            elif aline.startswith(name_prefix):
                name = str(aline).strip().split(":")[-1].split("/")[-1][:-3]       

    return (name, result)


def main():
    args = create_argument_parser().parse_args()

    logs_dir = pathlib.Path(args.logs_dir).resolve()
    if not logs_dir.is_dir():
        print(f"{logs_dir} is not a valid directory")
        return

    exp_hash_map_file = pathlib.Path(args.hash_data_file).resolve()
    if not exp_hash_map_file.is_file():
        print(f"{exp_hash_map_file} is not a valid file")
        return

    exp_hash_map = {}
    with exp_hash_map_file.open('rb') as fh:
        exp_hash_map = json.load(fh)

    out_dir = logs_dir / "processed_data"
    out_dir.mkdir(exist_ok=True)

    print("Processing routersploit logs...", end="", flush=True)
    processed_data = {"vulnerable": [], "not-vulnerable": [], "needs-verification": [], "error": []}
    for afile in logs_dir.iterdir():
        if afile.is_file() and afile.name.endswith(".stdout"):
            # TODO: Fix firmware ID extract if name of log file changes
            firmware_id = afile.name.rsplit('.', 1)[0]
            name, firmware_data = extract_exploit_status(afile, exp_hash_map)
            for status in processed_data:
                for exploit_data in firmware_data[status]:
                    exploit_name = exploit_data[0]
                    target_ip = exploit_data[1]
                    target_port = exploit_data[2]
                    processed_data[status].append((firmware_id, name, target_ip, target_port, exploit_name))

    print("done.")

    print("Dumping processed data to CSV...", end="", flush=True)
    csv_header = ["Firmware ID", "Name", "Target IP", "Target Port", "Exploit name"]
    error_out_file = out_dir / "error.csv"
    not_vulnerable_out_file = out_dir / "not-vulnerable.csv"
    needs_verification_out_file = out_dir / "needs-verification.csv"
    vulnerable_out_file = out_dir / "vulnerable.csv"

    if len(processed_data["error"]) > 0:
        with error_out_file.open('w') as fh:
            csvwriter = csv.writer(fh)
            csvwriter.writerow(csv_header)
            csvwriter.writerows(sorted(processed_data["error"]))

    with needs_verification_out_file.open('w') as fh:
        csvwriter = csv.writer(fh)
        csvwriter.writerow(csv_header)
        csvwriter.writerows(sorted(processed_data["needs-verification"]))

    with not_vulnerable_out_file.open('w') as fh:
        csvwriter = csv.writer(fh)
        csvwriter.writerow(csv_header)
        csvwriter.writerows(sorted(processed_data["not-vulnerable"]))

    with vulnerable_out_file.open('w') as fh:
        csvwriter = csv.writer(fh)
        csvwriter.writerow(csv_header)
        csvwriter.writerows(sorted(processed_data["vulnerable"]))

    print(f"done. See {out_dir}.")


if __name__ == "__main__":
    main()

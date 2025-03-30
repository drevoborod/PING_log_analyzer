#!/usr/bin/env python3
# Python 3.11+ required!

import argparse
import re
import sys
from contextlib import suppress
from pathlib import Path
from datetime import datetime
from statistics import median
from typing import Iterator


TITLE_REGEXP = r'^PING (.+) \([\d.:]+\) \d+.*'
DEFAULT_TIME_THRESHOLD = 1    # ms


class LogItem:
    __slots__ = ('log_string', 'ip', 'seq_number', 'time', 'timestamp', 'domain')
    LOG_COMPILED_REGEXP = re.compile(
        r'^(\[(?P<timestamp>\d+(\.\d+)?)\])?\s*\d+ \w+ \w+ (?P<domain>.+?)'
        r'( \((?P<ip>(\d{1,3}\.){3}\d{1,3}?|[:\dA-Fa-f]+)\))?: '
        r'icmp_seq=(?P<seq>\d+) ttl=\d+ time=(?P<time>\d+(\.\d+)?) .+$'
    )

    def __init__(self, log_string: str) -> None:
        self.log_string = log_string.strip()
        if not(log_item_match_object := self.LOG_COMPILED_REGEXP.match(self.log_string)):
            raise ValueError(f'Not a valid PING log string: "{self.log_string}"')
        log_data = log_item_match_object.groupdict()
        timestamp = log_data.get("timestamp")
        if timestamp:
            timestamp = datetime.fromtimestamp(float(timestamp))
        self.timestamp = timestamp
        self.ip = log_data.get("ip")
        self.seq_number = int(log_data.get("seq"))
        self.time = float(log_data.get("time"))
        self.domain = log_data.get("domain")


def create_title(file: Iterator[str]) -> str:
    line = ""
    while not re.match(TITLE_REGEXP, line):
        try:
            line = next(file)
        except StopIteration:
            raise ValueError("No PING title found")
    return "Statistics of " + line.rstrip("\n")


def parse_log(file: Iterator[str]) -> list[LogItem]:
    result = []
    while True:
        try:
            with suppress(ValueError):
                result.append(LogItem(next(file)))
        except StopIteration:
            return result


def format_timestamp(timestamp: datetime) -> str:
    return timestamp.strftime("%Y-%d-%m %H:%M:%S.%f: ")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('file_path', help='Path to PING log file.')
    parser.add_argument('-t', '--threshold', metavar='milliseconds', type=int,
                        help='Value in millisecondss. Values below this value are considered '
                             'as acceptable, values above are meant too high.',
                        default=DEFAULT_TIME_THRESHOLD)
    parser.add_argument("-s", "--skip_title", action="store_true", help="Skip PING log title")
    args = parser.parse_args()

    infile_object = Path(args.file_path)
    time_threshold = args.threshold

    title = ""
    with open(infile_object) as infile:
        file_iterator = iter(infile)
        if not args.skip_title:
            try:
                title = create_title(file_iterator)
            except ValueError:
                sys.exit("No PING title found, probably corrupted log file")
        parsed_log = parse_log(file_iterator)

    if parsed_log:
        records_above_threshold = []
        chunks_with_skips = []
        high_ping_counter = 0
        skip_counts = []
        previous_number = parsed_log[0].seq_number - 1
        previous_item = parsed_log[0]
        for log_item in parsed_log:
            if log_item.time > time_threshold:
                records_above_threshold.append(log_item)
                high_ping_counter += 1
            if log_item.seq_number != previous_number + 1:
                skipped_count = log_item.seq_number - previous_number - 1
                chunks_with_skips.append({'start': previous_item, 'end': log_item, 'skipped': skipped_count})
                skip_counts.append(skipped_count)
            previous_item = log_item
            previous_number = log_item.seq_number

        result = [title, "\n"] if title else []
        result.append(f'Total records: {len(parsed_log)}')
        parsed_log_times = [x.time for x in parsed_log]
        result.append(f'Average ping: {round(sum(parsed_log_times) / len(parsed_log), 3)}')
        result.append(f'Median ping: {median(parsed_log_times)}')
        result.append(f'Maximum ping: {max(parsed_log_times)}')
        result.append('')
        result.append(f'Total times above {time_threshold} ms: {len(records_above_threshold)}')
        if records_above_threshold:
            exceeding_times = [x.time for x in records_above_threshold]
            result.append(f'Percentage of requests above {time_threshold} ms: {len(records_above_threshold) * 100 / len(parsed_log):.2f}')
            result.append(f'Average ping above {time_threshold} ms: {round(sum(exceeding_times) / len(records_above_threshold), 3)}')
            result.append(f'Median ping above {time_threshold} ms: {median(exceeding_times)}')
        result.append('')
        result.append(f'Skipped requests chunks count: {len(chunks_with_skips)}')
        if chunks_with_skips:
            result.append(f'Average skipped requests in one chunk: {round(sum(skip_counts) / len(skip_counts), 3)}')
            result.append(f'Median skipped requests in one chunk: {median(skip_counts)}')
            result.append(f'Maximum skipped requests in one chunk: {max(skip_counts)}')
        result.append('')
        if records_above_threshold:
            result.append(f'\n__Times above {time_threshold} ms:__\n')
            result.extend([f'{format_timestamp(x.timestamp) if x.timestamp else ""}ping {x.ip if x.ip else x.domain}: seq={x.seq_number} time={x.time}' for x in records_above_threshold])
            result.append('')
        if chunks_with_skips:
            result.append('\n__Skipped requests:__\n')
            for item in chunks_with_skips:
                result.append(f'Chunk begin{" at " + format_timestamp(item["start"].timestamp) if item["start"].timestamp else ": "}ping {item["start"].ip if item["start"].ip else item["start"].domain}: seq={item["start"].seq_number} time={item["start"].time}')
                result.append(f'Skipped: {item["skipped"]}')
                result.append(f'Chunk end{" at " + format_timestamp(item["end"].timestamp) if item["end"].timestamp else ": "}ping {item["end"].ip if item["end"].ip else item["end"].domain}: seq={item["end"].seq_number} time={item["end"].time}')
                result.append('')

        outfile_object = Path(infile_object.parent / (infile_object.stem + '_analyzed.txt'))
        with open(outfile_object, 'w') as logfile:
            logfile.write('\n'.join(result))
        print(f'Analyze results saved to {outfile_object}')

    else:
        print(f'No PING log records found in provided file: {infile_object}')

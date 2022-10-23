#!/usr/bin/env python3
# Python 3.6+ required!

import argparse
import re
from contextlib import suppress
from pathlib import Path
from datetime import datetime
from statistics import median

# import os, psutil     # for performance measurements


REGEXP = r'^\d+ \w+ \w+ .*?(\d+\.\d+\.\d+\.\d+)\)?: icmp_seq=(\d+) ttl=\d+ time=([0-9.]+) .+$'
REGEXP_TIMESTAMP = r'^\[([0-9]+\.[0-9]+)] \d+ \w+ \w+ .*?(\d+\.\d+\.\d+\.\d+)\)?: icmp_seq=(\d+) ttl=\d+ time=([0-9.]+) .+$'
# LOG_PATTERN_DNS = re.compile(r'^\d+ \w+ \w+ (\d+\.\d+\.\d+\.\d+): icmp_seq=(\d+) ttl=\d+ time=([0-9.]+) .+$')
# LOG_PATTERN_DNS_TIMESTAMP = re.compile(r'^\[([0-9]+\.[0-9]+)] \d+ \w+ \w+ (\d+\.\d+\.\d+\.\d+): icmp_seq=(\d+) ttl=\d+ time=([0-9.]+) .+$')
DEFAULT_THRESHOLD = 1    # ms


class LogItem:

    __slots__ = ['log_string', 'ip', 'number', 'time', 'timestamp']

    def __init__(self, log_string, pattern, timestamp=True):
        self.log_string = log_string.strip()
        if not (log_item_match_object := pattern.match(self.log_string)):
            raise ValueError('Non-log string')
        log_data = log_item_match_object.groups()
        self.timestamp = datetime.fromtimestamp(float(log_data[0])) if timestamp else None
        self.ip = log_data[1 if timestamp else 0]
        self.number = int(log_data[2 if timestamp else 1])
        self.time = float(log_data[3 if timestamp else 2])


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('file_path', help='Path to PING log file.')
    parser.add_argument('-t', '--threshold', metavar='milliseconds', type=int,
                        help='Value in millisecondss. Values below this value are considered '
                             'as acceptable, values above are meant too high.',
                        default=DEFAULT_THRESHOLD)
    parser.add_argument('--timestamps', help='Whether there are timestamps in PING log.', action='store_true')
    parser.add_argument('--regexp', metavar='"regular expression"', help='Regexp for locating suitable records in PING log.')
    args = parser.parse_args()

    infile_object = Path(args.file_path)
    timestamp = args.timestamps
    if args.regexp:
        pattern = re.compile(args.regexp)
    else:
        pattern = re.compile(REGEXP_TIMESTAMP if timestamp else REGEXP)
    time_threshold = args.threshold

    parsed_log = []
    with open(infile_object) as infile:
        for string in infile:
            with suppress(ValueError):
                parsed_log.append(LogItem(string, pattern, timestamp))

    if parsed_log:
        records_above_threshold = []
        chunks_with_skips = []
        high_ping_counter = 0
        skip_counts = []
        previous_number = parsed_log[0].number - 1
        previous_item = parsed_log[0]
        for log_item in parsed_log:
            if log_item.time > time_threshold:
                records_above_threshold.append(log_item)
                high_ping_counter += 1
            if log_item.number != previous_number + 1:
                skipped_count = log_item.number - previous_number - 1
                chunks_with_skips.append({'start': previous_item, 'end': log_item, 'skipped': skipped_count})
                skip_counts.append(skipped_count)
            previous_item = log_item
            previous_number = log_item.number

        result = []
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
            result.extend([f'{x.timestamp} from {x.ip}: seq={x.number} time={x.time}' for x in records_above_threshold])
            result.append('')
        if chunks_with_skips:
            result.append('\n__Skipped requests:__\n')
            for item in chunks_with_skips:
                result.append(f'{item["start"].timestamp} from {item["start"].ip}: seq={item["start"].number} time={item["start"].time}')
                result.append(f'Skipped: {item["skipped"]}')
                result.append(f'{item["end"].timestamp} from {item["end"].ip}: seq={item["end"].number} time={item["end"].time}')
                result.append('')

        outfile_object = Path(infile_object.parent / (infile_object.stem + '_analyzed.txt'))
        with open(outfile_object, 'w') as logfile:
            logfile.write('\n'.join(result))
        print(f'Analyze results saved to {outfile_object}')

        ###
        # For performance measurements
        # print(psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2)
        ###

    else:
        print(f'No PING log records found in provided file: {infile_object}')

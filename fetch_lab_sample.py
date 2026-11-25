"""Terminal entry point: fetch the exported sample; do not store passwords."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from nexus.core import Invalid
from nexus.transfer import fetch_lab_sample


def main():
    parser = argparse.ArgumentParser(description='NEXUS: tải mẫu lab đã xuất, tự tạo thư mục đích')
    parser.add_argument('--host', required=True, help='IPv4 Ubuntu, ví dụ 192.168.157.130')
    parser.add_argument('--user', default='student')
    parser.add_argument('--port', type=int, default=22)
    args = parser.parse_args()
    try:
        result = fetch_lab_sample(args.host, args.user, args.port, interactive=True)
    except (Invalid, OSError) as error:
        parser.exit(1, 'NEXUS: ' + str(error) + '\n')
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()

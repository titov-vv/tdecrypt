#!/usr/bin/python
TELEGRAM_PATH = '/home/vtitov/.local/share/TelegramDesktop/tdata'
TEST_FILE_PATH = '/home/vtitov/.local/share/TelegramDesktop/tdata/user_data/media_cache/0/98/B339834CCE06'

import os
import logging
import argparse
from tprofile import TelegramProfile


def get_cmd_line_args():
    parser = argparse.ArgumentParser(
        usage="%(prog)s -p [profile]",
        description="Viewer for Telegram data folder"
    )
    parser.add_argument('-p', '--profile', required=True, metavar="XYZ",
                        help="Hex-name of a profile within Telegram folder")
    return parser.parse_args()


def main():
    LOGLEVEL = os.environ.get('LOGLEVEL', 'WARNING').upper()
    logging.basicConfig(level=LOGLEVEL)

    args = get_cmd_line_args()

    profile = TelegramProfile(TELEGRAM_PATH, args.profile)
    profile.load()

    profile.decryptTDEF(TEST_FILE_PATH)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

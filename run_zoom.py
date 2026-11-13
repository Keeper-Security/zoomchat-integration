# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Keeper Zoom App - Entry Point

Run this script to start the Keeper Zoom Team Chat integration.
Configure zoom_config.yaml (or set $ZOOM_CONFIG_PATH) before running.
"""

import warnings
warnings.filterwarnings("ignore", message=".*LibreSSL.*")
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")

import os

from src.app import KeeperZoomApp
from src.logger import logger


def main():
    """Start the Keeper Zoom App."""
    config_path = os.environ.get(
        "ZOOM_CONFIG_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "zoom_config.yaml"),
    )

    print("=" * 60)
    print("Starting Keeper Zoom App")
    print("=" * 60)
    logger.info(f"Config: {config_path}")
    print("=" * 60)

    app = KeeperZoomApp(config_path=config_path)
    app.start()


if __name__ == "__main__":
    main()

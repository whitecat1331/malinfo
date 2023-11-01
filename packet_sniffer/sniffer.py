import argparse
import os
import time

if not __name__ == "__main__":
    from packet_sniffer.core import PacketSniffer
    from packet_sniffer.output import OutputToScreen
else:
    from core import PacketSniffer
    from output import OutputToScreen

DURATION = 5


def main(duration=DURATION, queue=None, **kwargs):
    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Interface from which Ethernet frames will be captured (monitors "
             "all available interfaces by default)."
    )
    parser.add_argument(
        "-d", "--data",
        action="store_true",
        help="Output packet data during capture."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Redirect output to log file"
    )
    _args = parser.parse_args()

    if len(kwargs) > 0:
        _args.interface = kwargs["interface"]
        _args.data = kwargs["data"]
        _args.output = kwargs["output"]

    if os.getuid() != 0:
        raise SystemExit("Error: Permission denied. This application requires "
                         "administrator privileges to run.")

    output = OutputToScreen(
        subject=(sniffer := PacketSniffer()),
        display_data=_args.data
    )

    start_time = time.time()

    try:
        frames = []
        for _ in sniffer.listen(_args.interface):
            '''Iterate through the frames yielded by the listener in an 
            infinite cycle while feeding them to all registered observers 
            for further processing/output'''
            frames.append(output.info)
            run_time = time.time() - start_time
            if run_time >= duration:
                break

    finally:
        if queue:
            queue.put(frames)
        return frames


if __name__ == "__main__":
    main()

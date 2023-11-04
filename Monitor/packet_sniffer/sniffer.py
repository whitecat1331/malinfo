import argparse
import os
import time

if not __name__ == "__main__":
    from .core import PacketSniffer
    from .output import OutputToScreen
else:
    from core import PacketSniffer
    from output import OutputToScreen


def main(duration, interface=None, data=None):

    if os.getuid() != 0:
        raise SystemExit("Error: Permission denied. This application requires "
                         "administrator privileges to run.")

    output = OutputToScreen(
        subject=(sniffer := PacketSniffer()),
        display_data=data,
        redirect=True
    )

    start_time = time.time()

    try:
        frames = []
        for _ in sniffer.listen(interface):
            '''Iterate through the frames yielded by the listener in an 
            infinite cycle while feeding them to all registered observers 
            for further processing/output'''
            frames.append(output.info)
            run_time = time.time() - start_time
            if run_time >= duration:
                break

    finally:
        return frames


if __name__ == "__main__":
    main()

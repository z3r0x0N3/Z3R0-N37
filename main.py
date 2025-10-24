import argparse
import sys

def main():
    parser = argparse.ArgumentParser(
        description="Z3R0-N37: A Decentralized, Anonymous Command and Control Framework"
    )
    parser.add_argument(
        "module",
        choices=["ghost_comm", "c2"],
        help="The module to run"
    )
    parser.add_argument(
        "--persistent",
        action="store_true",
        help="Keep the selected module running indefinitely until manually stopped"
    )
    args = parser.parse_args()

    if args.module == "ghost_comm":
        from Ghost_Comm.main import main as ghost_comm_main
        print("Starting Ghost_Comm simulation...")
        ghost_comm_main(persistent=args.persistent)

    elif args.module == "c2":
        from c2 import main as c2_main
        print("Starting C2 server...")
        c2_main()

if __name__ == "__main__":
    main()


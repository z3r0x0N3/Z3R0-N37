import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Z3R0-N37: A Decentralized, Anonymous Command and Control Framework")
    parser.add_argument("module", choices=["ghost_comm", "c2"], help="The module to run")
    args = parser.parse_args()

    if args.module == "ghost_comm":
        from Ghost_Comm.main import main as ghost_comm_main
        print("Initialising G.C.N Framework")
        ghost_comm_main()
    elif args.module == "c2":
        from c2 import main as c2_main
        print("Starting Z3R0-N37 C2 server...")
        c2_main()

if __name__ == "__main__":
    main()

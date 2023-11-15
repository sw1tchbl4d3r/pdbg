class Colors:
    RESET     = "\033[0m"
    BOLD      = "\033[01m"
    UNDERLINE = "\033[04m"
    RED       = "\033[31m"
    GREEN     = "\033[32m"
    ORANGE    = "\033[33m"
    BLUE      = "\033[34m"
    PURPLE    = "\033[35m"
    CYAN      = "\033[36m"
    YELLOW    = "\033[93m"
    LRED      = "\033[91m"
    LGREEN    = "\033[92m"
    LBLUE     = "\033[94m"

PROMPT = f"{Colors.GREEN}{Colors.BOLD}dbg>{Colors.RESET} "

def log_info(message: str):
    print(f"[{Colors.BLUE}#{Colors.RESET}] {message}")

def log_error(message: str):
    print(f"[{Colors.RED}!{Colors.RESET}] {message}")

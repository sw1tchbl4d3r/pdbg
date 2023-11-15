from setuptools import setup, Extension

MODULE_NAME = "ipdbg"

def main():
    setup(name=MODULE_NAME,
          author="sw1tchbl4d3",
          ext_modules=[Extension(MODULE_NAME, ["ipdbgmodule.c"])])

if __name__ == "__main__":
    main()

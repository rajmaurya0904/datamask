"""Exception types shared across datamask."""


class DatamaskError(Exception):
    """Raised for bad input, bad configuration or unusable files.

    The command line turns these into a one-line message on stderr and exit code 2.
    """

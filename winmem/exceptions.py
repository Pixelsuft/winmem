class NoArgsSend(Exception):
    """No args was send to function"""

    def __init__(self, *args):
        super().__init__(*args)


class ProcessNotFound(Exception):
    """If process not found"""

    def __init__(self, *args):
        super().__init__(*args)


class ModuleNotFound(Exception):
    """If module not found"""

    def __init__(self, *args):
        super().__init__(*args)


class ModuleBaseNotFound(Exception):
    """If module base not found"""

    def __init__(self, *args):
        super().__init__(*args)


class ProcessError(Exception):
    """Something wrong"""

    def __init__(self, *args):
        super().__init__(*args)

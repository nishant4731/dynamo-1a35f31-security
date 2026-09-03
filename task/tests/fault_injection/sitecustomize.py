"""Verifier-only deterministic process-death cut after a non-exchange rename."""

import ctypes
import os
import signal


if os.environ.get("ROOTFS_PUBLISH_FAULT") == "post-rename":
    _rename = os.rename
    _replace = os.replace
    _cdll = ctypes.CDLL
    _rename_count = 0
    _RENAME_EXCHANGE = 2
    _RENAMEAT2_SYSCALLS = {276, 316}  # Linux aarch64 and x86_64.

    def _integer(value):
        return int(getattr(value, "value", value))

    def _crash():
        global _rename_count
        _rename_count += 1
        if _rename_count == 1:
            os.kill(os.getpid(), signal.SIGKILL)

    def _crash_after(function):
        def wrapped(*args, **kwargs):
            result = function(*args, **kwargs)
            _crash()
            return result
        return wrapped

    class _FunctionProxy:
        """Forward ctypes metadata while observing successful rename syscalls."""

        def __init__(self, function, name):
            object.__setattr__(self, "_function", function)
            object.__setattr__(self, "_name", name)

        def __getattr__(self, name):
            return getattr(self._function, name)

        def __setattr__(self, name, value):
            setattr(self._function, name, value)

        def __call__(self, *args):
            result = self._function(*args)
            if result != 0:
                return result
            if self._name == "renameat2":
                if not (_integer(args[4]) & _RENAME_EXCHANGE):
                    _crash()
            elif self._name == "syscall":
                if (
                    len(args) >= 6
                    and _integer(args[0]) in _RENAMEAT2_SYSCALLS
                    and not (_integer(args[5]) & _RENAME_EXCHANGE)
                ):
                    _crash()
            else:
                _crash()
            return result

    class _LibraryProxy:
        def __init__(self, library):
            object.__setattr__(self, "_library", library)

        def __getattr__(self, name):
            function = getattr(self._library, name)
            if name in {"rename", "renameat", "renameat2", "syscall"}:
                return _FunctionProxy(function, name)
            return function

    def _observed_cdll(*args, **kwargs):
        return _LibraryProxy(_cdll(*args, **kwargs))

    os.rename = _crash_after(_rename)
    os.replace = _crash_after(_replace)
    ctypes.CDLL = _observed_cdll

"""Spawn-safe fake reviewer: do not import mitmproxy, Pillow or model modules here.

Spawn unpickles factories by importing their defining module. Keeping this tiny
avoids making worker lifecycle guards pay for the entire test suite's imports.
"""

class ProcessReviewer:
    def __init__(self, **options):
        pass

    def review(self, data):
        import os
        import time
        if data == b'crash':
            os._exit(23)
        if data == b'hang':
            time.sleep(30)
        if data == b'invalid':
            raise ValueError('cannot decode')
        return False, [str(os.getpid())]


class BillingError(RuntimeError):
    """Same name as aifilter.ytcheck.BillingError, which is what the pool reports."""


class BillingReviewer:
    def __init__(self, **options):
        pass

    def review(self, data):
        raise BillingError('402 credit_balance')

import time


class TimeoutException(Exception):
    pass


def wait_while(condition, refresh=lambda: True):
    def waitfor(timeout):
        waited = 0
        SLEEPTIME = 5

        refresh()
        if not condition():
            return True

        while waited < timeout and condition():
            time.sleep(SLEEPTIME)
            waited += SLEEPTIME
            refresh()
        if condition():
            raise TimeoutException()

    return waitfor
